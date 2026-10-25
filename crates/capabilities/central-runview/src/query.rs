//! `central-runview` query helpers — the pure, projection-facing
//! vocabulary the run surfaces share: the opaque keyset cursor codec
//! for `list_runs` (the typed `SeekCursor` polling contract) and the
//! page bounds every handler applies.
//!
//! The codec is upstream's `encodeRunCursor`/`decodeRunCursor`
//! verbatim: `"<rfc3339nano>_<uuid>"`. The token is URL-safe as-is —
//! `T`, `-`, `:`, `.`, `Z`, `_`, and the UUID's hex/dash alphabet all
//! survive a raw query component unencoded.

use central_foundation::failure::Failure;
use central_foundation::identity::RunId;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::domain::RunCursor;

/// `runListPageSize` — bounds one run-list page. The handler fetches
/// one row past it to detect the next page, so the rendered page never
/// carries a lookahead row.
pub const RUN_LIST_PAGE_SIZE: i64 = 50;

/// `runDetailEventLimit` — bounds the rendered event timeline of the
/// run detail page; the journal itself is read in full (the divergence
/// fold needs it all) — only the rendered rows are capped, with the
/// total shown.
pub const RUN_DETAIL_EVENT_LIMIT: usize = 500;

/// `fleetDeferredRunScanLimit` — bounds how many of the workspace's
/// newest runs the fleet page probes for deferred admissions. Deferrals
/// are per-run journaled events, so the page composes the
/// workspace-wide view from a bounded run scan rather than a dedicated
/// projection; deferral residue older than the newest page is history
/// the run detail page already owns.
pub const FLEET_DEFERRED_RUN_SCAN_LIMIT: i64 = 25;

/// The `RUNVIEW_CURSOR_INVALID` failure code a malformed cursor token
/// decodes to — the handler maps it to the same generic 404 as a
/// malformed id (a silently-reset first page would present page-1 data
/// under a page-N URL).
pub const RUNVIEW_CURSOR_INVALID: &str = "RUNVIEW_CURSOR_INVALID";

/// `encodeRunCursor` — renders the keyset cursor as an opaque
/// `"<rfc3339nano>_<uuid>"` token. RFC3339 emits sub-second digits only
/// when non-zero, exactly like Go's `time.RFC3339Nano`.
#[must_use]
pub fn encode_run_cursor(cursor: &RunCursor) -> String {
    let ts = cursor
        .created_at
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_default();
    format!("{ts}_{}", cursor.id)
}

/// `decodeRunCursor` — parses the token back into a [`RunCursor`].
/// `None` input is the first page (`Ok(None)`); a malformed token is an
/// `invalid` failure — never silently treated as the first page.
///
/// `RunId::parse` enforces the UUIDv7 newtype rule; upstream's
/// `uuid.FromString` accepts any version, but every cursor this surface
/// mints carries a v7 id and rejecting a foreign-version token matches
/// the identity boundary's strictness.
pub fn decode_run_cursor(raw: Option<&str>) -> Result<Option<RunCursor>, Failure> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.is_empty() {
        return Ok(None);
    }
    let invalid = |detail: &'static str| Failure::invalid(RUNVIEW_CURSOR_INVALID, detail);
    let (ts, id) = raw
        .split_once('_')
        .ok_or_else(|| invalid("run cursor: missing separator"))?;
    let created_at =
        OffsetDateTime::parse(ts, &Rfc3339).map_err(|_| invalid("run cursor: bad timestamp"))?;
    let id = RunId::parse(id).map_err(|_| invalid("run cursor: bad id"))?;
    Ok(Some(RunCursor { created_at, id }))
}

/// `runViewStatusLabel` — maps the v33 `runs.status` vocabulary to a
/// human label. The token itself is always rendered next to it; an
/// unknown value fails closed to the raw string so a new state is never
/// blank.
#[must_use]
pub fn run_view_status_label(status: &str) -> &str {
    match status {
        "queued" => "Queued",
        "running" => "Running",
        "waiting" => "Waiting",
        "cancelling" => "Cancelling",
        "succeeded" => "Succeeded",
        "failed" => "Failed",
        "failed_terminal" => "Failed terminally",
        "cancelled" => "Cancelled",
        other => other,
    }
}

/// The v33 `workflow_nodes_state_check` vocabulary in declaration
/// order — the fixed display order of the per-run census.
pub const RUN_NODE_STATE_ORDER: [&str; 8] = [
    "declared",
    "ready",
    "dispatched",
    "running",
    "succeeded",
    "failed_terminal",
    "attempt_ambiguous",
    "cancelled",
];

/// Whether `state` is inside the canonical v33 node vocabulary.
#[must_use]
pub fn known_run_node_state(state: &str) -> bool {
    RUN_NODE_STATE_ORDER.contains(&state)
}

/// `fleetRunLive` — whether a run status admits live deferral residue:
/// terminal runs keep their journaled `admission_deferred` events
/// forever, but a finished run's claim queue is resolved history, not
/// pressure. Unknown statuses fail open — a novel status is live until
/// declared terminal in the vocabulary.
#[must_use]
pub fn fleet_run_live(status: &str) -> bool {
    !matches!(
        status,
        "succeeded" | "failed" | "failed_terminal" | "cancelled"
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use central_foundation::failure::FailureKind;

    /// `TestRunCursorRoundTrip` — the opaque token decodes back to the
    /// same `(created_at, id)` keyset position.
    #[test]
    fn cursor_round_trip() {
        let cursor = RunCursor {
            created_at: OffsetDateTime::now_utc(),
            id: RunId::new(),
        };
        let token = encode_run_cursor(&cursor);
        let back = decode_run_cursor(Some(&token)).unwrap().unwrap();
        assert_eq!(back.id, cursor.id);
        // RFC3339 nano keeps sub-second precision for keyset ordering.
        assert_eq!(
            back.created_at.unix_timestamp_nanos(),
            cursor.created_at.unix_timestamp_nanos()
        );
    }

    /// `TestRunCursorFirstPage` — absent and empty tokens both mean
    /// page one (`Ok(None)`).
    #[test]
    fn cursor_absent_is_first_page() {
        assert_eq!(decode_run_cursor(None).unwrap(), None);
        assert_eq!(decode_run_cursor(Some("")).unwrap(), None);
    }

    /// `TestRunCursorMalformed` — every malformed shape is the same
    /// `RUNVIEW_CURSOR_INVALID` failure, never a silent page-one reset.
    #[test]
    fn cursor_malformed_is_invalid() {
        for token in [
            "not-a-cursor",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z_not-a-uuid",
            "garbage_018e5f5a-7c3b-7f2a-9d4e-1a2b3c4d5e6f",
            "2024-13-99T99:99:99Z_018e5f5a-7c3b-7f2a-9d4e-1a2b3c4d5e6f",
        ] {
            let err = decode_run_cursor(Some(token)).unwrap_err();
            assert_eq!(err.kind(), FailureKind::Invalid, "{token}");
            assert_eq!(err.code(), RUNVIEW_CURSOR_INVALID, "{token}");
        }
    }

    /// The node-state vocabulary stays in the schema's declaration
    /// order (the census renders counts in this fixed order).
    #[test]
    fn node_state_order_is_canonical() {
        assert!(known_run_node_state("attempt_ambiguous"));
        assert!(!known_run_node_state("exploded"));
        assert_eq!(RUN_NODE_STATE_ORDER[0], "declared");
    }

    /// `fleetRunLive` — terminal statuses shed deferral residue; the
    /// rest are live.
    #[test]
    fn fleet_run_live_states() {
        for s in ["succeeded", "failed", "failed_terminal", "cancelled"] {
            assert!(!fleet_run_live(s), "{s}");
        }
        for s in ["queued", "running", "waiting", "cancelling", "novel"] {
            assert!(fleet_run_live(s), "{s}");
        }
    }
}
