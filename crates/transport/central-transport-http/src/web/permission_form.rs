//! Form parsers for the submit/permission/resolve routes
//! (`permission_form.go`). Every field must appear at most once —
//! ambiguity is never silently picked.

use std::collections::HashMap;

use central_foundation::identity::HarnessPermissionApprovalId;
use central_task::domain::PermissionPolicy;

use super::form_value;

/// `parsePermissionPolicy` — empty means deny; any other value must be a
/// declared policy (decision 4).
#[must_use]
pub fn parse_permission_policy(raw: &str) -> Option<PermissionPolicy> {
    if raw.is_empty() {
        return Some(PermissionPolicy::Deny);
    }
    let p = PermissionPolicy::parse(raw);
    p.known().then_some(p)
}

/// The decision route's parsed form.
pub struct PermissionDecisionForm {
    /// The approval being answered.
    pub approval_id: HarnessPermissionApprovalId,
    /// The posted hex MAC.
    pub input_mac: String,
    /// Allow (`true`) or deny (`false`).
    pub allow: bool,
}

/// `parsePermissionDecision` — `approval_id`, `input_mac`, and
/// `decision` (`allow`|`deny`) each exactly once.
#[must_use]
pub fn parse_permission_decision(
    form: &HashMap<String, Vec<String>>,
) -> Option<PermissionDecisionForm> {
    for name in ["approval_id", "input_mac", "decision"] {
        if form.get(name).map_or(0, Vec::len) != 1 {
            return None;
        }
    }
    let approval_id = HarnessPermissionApprovalId::parse(form_value(form, "approval_id")).ok()?;
    let allow = match form_value(form, "decision") {
        "allow" => true,
        "deny" => false,
        _ => return None,
    };
    Some(PermissionDecisionForm {
        approval_id,
        input_mac: form_value(form, "input_mac").to_string(),
        allow,
    })
}

/// The resolve form's action values — one per button.
pub const RESOLVE_ACTION_FAIL: &str = "fail";
/// `action=cancel`.
pub const RESOLVE_ACTION_CANCEL: &str = "cancel";
/// `action=rerun` — "Mark failed and rerun (operator resolved)".
pub const RESOLVE_ACTION_RERUN: &str = "rerun";

/// `parseResolveAction` — the optional `action` field: absent, `fail`,
/// `cancel`, or `rerun`, at most once. `Ok(None)` means absent; `Err`
/// means malformed (repeated or unrecognized).
/// The `action` field was repeated or unrecognized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedAction;

pub fn parse_resolve_action(
    form: &HashMap<String, Vec<String>>,
) -> Result<Option<&str>, MalformedAction> {
    let values = form.get("action").map_or(&[][..], Vec::as_slice);
    match values {
        [] => Ok(None),
        [one] => match one.as_str() {
            s @ (RESOLVE_ACTION_FAIL | RESOLVE_ACTION_CANCEL | RESOLVE_ACTION_RERUN) => Ok(Some(s)),
            _ => Err(MalformedAction),
        },
        _ => Err(MalformedAction),
    }
}
