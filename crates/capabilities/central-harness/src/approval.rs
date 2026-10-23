//! The durable operator permission gate — the port of
//! `internal/harness/approval.go` (harness phase 3c decisions 5, 6, 8, 9,
//! 11 and 13). [`PermissionApproval`] is the durable question "may the
//! harness run this tool with this input", and its answer; the input
//! itself is never part of it, only its [`InputMac`] and size. All
//! mutators are pure and return `Err` on failure; `version` is owned by
//! the store.

use std::fmt;

use central_foundation::failure::Failure;
use central_foundation::identity::{
    HarnessAttemptId, HarnessPermissionApprovalId, RunId, TaskId, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::domain::{codes, is_zero_time, vocab};

// Approval bounds and decider values — harness phase 3c decisions 5, 8,
// 9, 11 and 13.

/// `harness.MaxPermissionRequestIDBytes` — bound on a harness-controlled
/// request id; a request past it is a protocol error.
pub const MAX_PERMISSION_REQUEST_ID_BYTES: usize = 512;

/// `harness.MaxToolCallIDBytes` — bound on a harness-controlled tool
/// call id.
pub const MAX_TOOL_CALL_ID_BYTES: usize = 512;

/// `harness.MaxToolNameBytes` — bound on a harness-controlled tool name.
pub const MAX_TOOL_NAME_BYTES: usize = 256;

/// `harness.MaxPermissionResources` — bound on the resource list.
pub const MAX_PERMISSION_RESOURCES: usize = 16;

/// `harness.MaxPermissionResourceBytes` — bound on one resource
/// spelling.
pub const MAX_PERMISSION_RESOURCE_BYTES: usize = 1 << 10;

/// `harness.MaxBridgedInputBytes` — the bridged-input limit (decision
/// 13): an input over it is denied at once and never bridged.
pub const MAX_BRIDGED_INPUT_BYTES: usize = 256 << 10;

/// `harness.MaxDecidedByBytes` — bound on the recorded decider.
pub const MAX_DECIDED_BY_BYTES: usize = 256;

/// `harness.DecidedByTimeout` — the decider recorded for an expiry.
pub const DECIDED_BY_TIMEOUT: &str = "policy:timeout";

/// `harness.DecidedByInputTooLarge` — the decider recorded for an
/// over-limit bridged input.
pub const DECIDED_BY_INPUT_TOO_LARGE: &str = "policy:input_too_large";

/// `harness.DecidedBySuperseded` — the decider recorded for a
/// supersession.
pub const DECIDED_BY_SUPERSEDED: &str = "system:superseded";

/// The upstream `decidedByOperatorPrefix`.
const DECIDED_BY_OPERATOR_PREFIX: &str = "operator-session:";

/// `harness.OperatorDecider`: returns the `decided_by` of an operator
/// decision taken in the session of `principal`. The principal comes
/// from the validated session, never from a form field; it must be
/// non-empty printable ASCII and keep the result within
/// [`MAX_DECIDED_BY_BYTES`].
pub fn operator_decider(principal: &str) -> Result<String, Failure> {
    if principal.is_empty()
        || !printable_ascii(principal)
        || DECIDED_BY_OPERATOR_PREFIX.len() + principal.len() > MAX_DECIDED_BY_BYTES
    {
        return Err(Failure::invalid(
            codes::INVALID_APPROVAL,
            format!(
                "operator principal must be 1..{} printable ASCII bytes",
                MAX_DECIDED_BY_BYTES - DECIDED_BY_OPERATOR_PREFIX.len()
            ),
        ));
    }
    Ok(format!("{DECIDED_BY_OPERATOR_PREFIX}{principal}"))
}

/// `harness.IsOperatorDecider`: `true` when `decided_by` names an
/// operator session — the prefix and a non-empty principal, all
/// printable ASCII as [`operator_decider`] builds it. `validate` applies
/// it to stored rows too.
#[must_use]
pub fn is_operator_decider(decided_by: &str) -> bool {
    decided_by.starts_with(DECIDED_BY_OPERATOR_PREFIX)
        && decided_by.len() > DECIDED_BY_OPERATOR_PREFIX.len()
        && printable_ascii(decided_by)
}

/// `harness.printableASCII`: `s` holds only bytes `0x20..=0x7e`.
pub(crate) fn printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// `harness.MinInputMACKeyBytes`: the shortest key
/// [`compute_input_mac`] accepts.
pub const MIN_INPUT_MAC_KEY_BYTES: usize = 32;

/// `harness.InputMAC`: HMAC-SHA256 over a tool input's raw bytes, keyed
/// by a random key serve generates once per process and never stores
/// (decision 5). A plain hash would let whoever reads the database or
/// the page confirm a guessed low-entropy secret; the MAC does not. It
/// is not secret itself.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputMac(pub [u8; 32]);

impl InputMac {
    /// The zero MAC — `harness.InputMAC{}`.
    pub const ZERO: Self = Self([0; 32]);

    /// `harness.InputMAC.Equal`: constant-time comparison.
    #[must_use]
    pub fn equal(&self, other: &InputMac) -> bool {
        // hmac.Equal → the sha2 crate's CtEq via subtle-style compare:
        // fold the xor — constant in the fixed 32-byte length.
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// `harness.InputMAC.IsZero`.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

impl fmt::Display for InputMac {
    /// The lower-case hex form a decision form posts — upstream
    /// `InputMAC.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for InputMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// `harness.ComputeInputMAC`: the MAC of `input` under `key`. A key
/// shorter than [`MIN_INPUT_MAC_KEY_BYTES`] is refused.
pub fn compute_input_mac(key: &[u8], input: &[u8]) -> Result<InputMac, Failure> {
    if key.len() < MIN_INPUT_MAC_KEY_BYTES {
        return Err(Failure::invalid(
            codes::INVALID_APPROVAL,
            format!("input MAC key must be at least {MIN_INPUT_MAC_KEY_BYTES} bytes"),
        ));
    }
    // HMAC-SHA256 keyed by `key` — RFC 2104, without the hmac crate
    // (sha2 is the approved dependency): HMAC = H((k^opad) ||
    // H((k^ipad) || m)), the key hashed first if longer than the block.
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(input);
    let inner_sum = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_sum);
    Ok(InputMac(outer.finalize().into()))
}

/// `harness.ParseInputMAC`: parses the hex form [`InputMac`]'s `Display`
/// produces.
pub fn parse_input_mac(s: &str) -> Result<InputMac, Failure> {
    if s.len() != 64 {
        return Err(Failure::invalid(
            codes::INVALID_APPROVAL,
            "input MAC must be 64 hex digits",
        ));
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16);
        let lo = (bytes[2 * i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(hi), Some(lo)) => *byte = ((hi << 4) | lo) as u8,
            _ => {
                return Err(Failure::invalid(
                    codes::INVALID_APPROVAL,
                    "input MAC is not hex",
                ));
            }
        }
    }
    Ok(InputMac(out))
}

vocab! {
    /// The lifecycle state of one permission approval — upstream
    /// `ApprovalState`.
    ApprovalState {
        /// `pending`.
        Pending => "pending",
        /// `allowed`.
        Allowed => "allowed",
        /// `denied`.
        Denied => "denied",
        /// `expired`.
        Expired => "expired",
        /// `superseded`.
        Superseded => "superseded",
    }
}

impl ApprovalState {
    /// `harness.ApprovalState.IsTerminal`: every state but pending is
    /// final.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        self.known() && !matches!(self, Self::Pending)
    }

    /// `harness.ApprovalState.Allows`: whether the state answers the
    /// harness with an allow.
    #[must_use]
    pub const fn allows(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// One durable harness permission approval — upstream
/// `PermissionApproval` (decision 6). `decided_at`/`decided_by` are set
/// exactly for a decided approval; `None`/empty pending.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermissionApproval {
    /// The approval's id.
    pub id: HarnessPermissionApprovalId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The attempt that asked.
    pub attempt_id: HarnessAttemptId,
    /// The task the attempt serves.
    pub task_id: TaskId,
    /// The run the attempt belongs to.
    pub run_id: RunId,
    /// The harness's request id.
    pub request_id: String,
    /// The tool call the request is about.
    pub tool_call_id: String,
    /// The tool name.
    pub tool_name: String,
    /// The keyed MAC of the input the operator saw.
    pub input_mac: InputMac,
    /// The input's size in bytes.
    pub input_size: i64,
    /// The lifecycle state.
    pub state: ApprovalState,
    /// When the harness asked.
    pub requested_at: OffsetDateTime,
    /// When the request times out.
    pub expires_at: OffsetDateTime,
    /// When the answer was recorded — `None` while pending (the Go zero
    /// time).
    pub decided_at: Option<OffsetDateTime>,
    /// Who answered — an [`operator_decider`] string or a fixed
    /// policy/system decider.
    pub decided_by: String,
    /// The persistence revision — owned by the store.
    pub version: i64,
}

/// Everything needed to open a pending approval — upstream
/// `OpenApprovalInput`.
#[derive(Debug, Clone)]
pub struct OpenApprovalInput {
    /// The approval's id.
    pub id: HarnessPermissionApprovalId,
    /// The owning workspace.
    pub workspace_id: WorkspaceId,
    /// The attempt that asked.
    pub attempt_id: HarnessAttemptId,
    /// The task the attempt serves.
    pub task_id: TaskId,
    /// The run the attempt belongs to.
    pub run_id: RunId,
    /// The harness's request id.
    pub request_id: String,
    /// The tool call the request is about.
    pub tool_call_id: String,
    /// The tool name.
    pub tool_name: String,
    /// The keyed MAC of the input the operator will see.
    pub input_mac: InputMac,
    /// The input's size in bytes.
    pub input_size: i64,
    /// When the harness asked.
    pub requested_at: OffsetDateTime,
    /// When the request times out.
    pub expires_at: OffsetDateTime,
}

/// An operator's answer to a pending approval — upstream
/// `ApprovalDecision`. `input_mac` is the MAC the operator's page was
/// rendered with; `decided_by` is [`operator_decider`] of the session's
/// principal.
#[derive(Debug, Clone)]
pub struct ApprovalDecision {
    /// `true` to allow, `false` to deny.
    pub allow: bool,
    /// The MAC the operator's page was rendered with.
    pub input_mac: InputMac,
    /// [`operator_decider`] of the session's principal.
    pub decided_by: String,
}

impl PermissionApproval {
    /// `harness.OpenApproval`: opens a pending approval.
    pub fn open(input: OpenApprovalInput) -> Result<Self, Failure> {
        let a = Self {
            id: input.id,
            workspace_id: input.workspace_id,
            attempt_id: input.attempt_id,
            task_id: input.task_id,
            run_id: input.run_id,
            request_id: input.request_id,
            tool_call_id: input.tool_call_id,
            tool_name: input.tool_name,
            input_mac: input.input_mac,
            input_size: input.input_size,
            state: ApprovalState::Pending,
            requested_at: input.requested_at,
            expires_at: input.expires_at,
            decided_at: None,
            decided_by: String::new(),
            version: 0,
        };
        a.checked()
    }

    /// `harness.Decide`: records an operator decision — pending →
    /// allowed or denied. Refused unless the approval is pending and
    /// unexpired at `at`, the decider is an operator session, and the
    /// MAC is the approval's own.
    pub fn decide(&self, d: ApprovalDecision, at: OffsetDateTime) -> Result<Self, Failure> {
        self.guard_pending(at)?;
        if at >= self.expires_at {
            return Err(Failure::conflict(
                codes::APPROVAL_NOT_PENDING,
                "approval expired",
            ));
        }
        if !is_operator_decider(&d.decided_by) {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "a decision needs an operator decider",
            ));
        }
        if !d.input_mac.equal(&self.input_mac) {
            return Err(Failure::conflict(
                codes::INPUT_MAC_MISMATCH,
                "permission decision does not match the requested input",
            ));
        }
        let state = if d.allow {
            ApprovalState::Allowed
        } else {
            ApprovalState::Denied
        };
        self.close(state, &d.decided_by, at)
    }

    /// `harness.Expire`: records the timeout's answer (decision 9) —
    /// pending → expired by `policy:timeout`, once `expires_at` has
    /// passed.
    pub fn expire(&self, at: OffsetDateTime) -> Result<Self, Failure> {
        self.guard_pending(at)?;
        if at < self.expires_at {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "approval has not expired yet",
            ));
        }
        self.close(ApprovalState::Expired, DECIDED_BY_TIMEOUT, at)
    }

    /// `harness.Supersede`: closes an approval whose attempt ended or
    /// became ambiguous without an answer (decision 11) — pending →
    /// superseded by `system:superseded`.
    pub fn supersede(&self, at: OffsetDateTime) -> Result<Self, Failure> {
        self.guard_pending(at)?;
        self.close(ApprovalState::Superseded, DECIDED_BY_SUPERSEDED, at)
    }

    fn guard_pending(&self, at: OffsetDateTime) -> Result<(), Failure> {
        if self.state != ApprovalState::Pending {
            return Err(Failure::conflict(
                codes::APPROVAL_NOT_PENDING,
                format!("approval is {}", self.state.as_str()),
            ));
        }
        if is_zero_time(at) {
            return Err(Failure::invalid(codes::INVALID_APPROVAL, "zero timestamp"));
        }
        Ok(())
    }

    fn close(
        &self,
        state: ApprovalState,
        decided_by: &str,
        at: OffsetDateTime,
    ) -> Result<Self, Failure> {
        let mut next = self.clone();
        next.state = state;
        next.decided_by = decided_by.to_string();
        next.decided_at = Some(at.max(self.requested_at));
        next.checked()
    }

    /// `harness.PermissionApproval.Validate`: every invariant the
    /// database also pins (migration b31).
    pub fn validate(&self) -> Result<(), Failure> {
        if self.id.is_nil()
            || self.workspace_id.is_nil()
            || self.attempt_id.is_nil()
            || self.task_id.is_nil()
            || self.run_id.is_nil()
        {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "approval, workspace, attempt, task and run ids are required",
            ));
        }
        if self.request_id.is_empty() || self.request_id.len() > MAX_PERMISSION_REQUEST_ID_BYTES {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                format!("request id must be 1..{MAX_PERMISSION_REQUEST_ID_BYTES} bytes"),
            ));
        }
        if self.tool_call_id.len() > MAX_TOOL_CALL_ID_BYTES {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                format!("tool call id exceeds {MAX_TOOL_CALL_ID_BYTES} bytes"),
            ));
        }
        if self.tool_name.len() > MAX_TOOL_NAME_BYTES || !printable_ascii(&self.tool_name) {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                format!("tool name must be at most {MAX_TOOL_NAME_BYTES} printable ASCII bytes"),
            ));
        }
        if self.input_mac.is_zero() {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "input MAC is required",
            ));
        }
        if self.input_size < 0 || self.input_size > MAX_BRIDGED_INPUT_BYTES as i64 {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                format!("input size must be 0..{MAX_BRIDGED_INPUT_BYTES}"),
            ));
        }
        if !self.state.known() {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                format!("unknown state {}", self.state.as_str()),
            ));
        }
        if is_zero_time(self.requested_at) || self.expires_at <= self.requested_at {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "expiry must follow the request",
            ));
        }
        if self.version < 0 {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "version must be >= 0",
            ));
        }
        let pending = self.state == ApprovalState::Pending;
        if pending != self.decided_at.is_none() || pending != self.decided_by.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "decision time and decider must be set exactly for a decided approval",
            ));
        }
        if self.decided_by.len() > MAX_DECIDED_BY_BYTES {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                format!("decider exceeds {MAX_DECIDED_BY_BYTES} bytes"),
            ));
        }
        match self.state {
            ApprovalState::Allowed | ApprovalState::Denied => {
                if !is_operator_decider(&self.decided_by) {
                    return Err(Failure::invalid(
                        codes::INVALID_APPROVAL,
                        format!("{} requires an operator decider", self.state.as_str()),
                    ));
                }
            }
            ApprovalState::Expired if self.decided_by != DECIDED_BY_TIMEOUT => {
                return Err(Failure::invalid(
                    codes::INVALID_APPROVAL,
                    format!("expired requires {DECIDED_BY_TIMEOUT}"),
                ));
            }
            ApprovalState::Superseded if self.decided_by != DECIDED_BY_SUPERSEDED => {
                return Err(Failure::invalid(
                    codes::INVALID_APPROVAL,
                    format!("superseded requires {DECIDED_BY_SUPERSEDED}"),
                ));
            }
            _ => {}
        }
        if !pending && self.decided_at.is_some_and(|d| d < self.requested_at) {
            return Err(Failure::invalid(
                codes::INVALID_APPROVAL,
                "decision precedes the request",
            ));
        }
        Ok(())
    }

    fn checked(self) -> Result<Self, Failure> {
        self.validate()?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domain::codes;
    use crate::testkit::{
        Mutation, approval_t0, is_code, nil_approval_id, nil_task_id, ok, operator,
        pending_approval, test_mac_key,
    };

    // Ports upstream `TestApprovalStatesAreClosed`.
    #[test]
    fn approval_states_are_closed() {
        let want = ["pending", "allowed", "denied", "expired", "superseded"];
        let got = ApprovalState::all();
        assert_eq!(got.len(), want.len(), "ApprovalStates() = {got:?}");
        for (state, name) in got.iter().zip(want.iter()) {
            assert_eq!(state.as_str(), *name);
            assert!(state.known(), "{state}: not known");
            assert_ne!(
                state.is_terminal(),
                *state == ApprovalState::Pending,
                "{state} is_terminal"
            );
        }
        assert!(!ApprovalState::parse("zombie").known());
        assert!(!ApprovalState::Unset.is_terminal());
        assert!(ApprovalState::Allowed.allows());
        assert!(!ApprovalState::Expired.allows());
        assert!(!ApprovalState::Denied.allows());
    }

    // Ports upstream `TestOpenApprovalIsPendingAndValidated`.
    #[test]
    fn open_approval_is_pending_and_validated() {
        let a = pending_approval();
        assert_eq!(a.state, ApprovalState::Pending);
        assert!(a.decided_at.is_none());
        assert_eq!(a.decided_by, "");
        assert_eq!(a.version, 0);
        let base = OpenApprovalInput {
            id: a.id,
            workspace_id: a.workspace_id,
            attempt_id: a.attempt_id,
            task_id: a.task_id,
            run_id: a.run_id,
            request_id: "req".to_string(),
            tool_call_id: String::new(),
            tool_name: "Bash".to_string(),
            input_mac: a.input_mac,
            input_size: 1,
            requested_at: approval_t0(),
            expires_at: approval_t0() + Duration::minutes(1),
        };
        let mutations: [Mutation<OpenApprovalInput>; 12] = [
            ("zero id", |i| i.id = nil_approval_id()),
            ("zero task", |i| i.task_id = nil_task_id()),
            ("empty request", |i| i.request_id = String::new()),
            ("oversize request", |i| i.request_id = "r".repeat(513)),
            ("oversize tool call", |i| i.tool_call_id = "t".repeat(513)),
            ("oversize tool", |i| i.tool_name = "n".repeat(257)),
            ("unprintable tool", |i| i.tool_name = "Ba\x1bsh".to_string()),
            ("zero mac", |i| i.input_mac = InputMac::ZERO),
            ("negative size", |i| i.input_size = -1),
            ("oversize input", |i| {
                i.input_size = MAX_BRIDGED_INPUT_BYTES as i64 + 1
            }),
            ("expiry at request", |i| i.expires_at = i.requested_at),
            ("zero requested time", |i| {
                i.requested_at = crate::domain::ZERO_TIME
            }),
        ];
        for (name, mutate) in mutations {
            let mut input = base.clone();
            mutate(&mut input);
            let err = PermissionApproval::open(input).unwrap_err();
            assert!(
                is_code(&err, codes::INVALID_APPROVAL),
                "{name}: err = {err}"
            );
        }
    }

    // Ports upstream `TestDecideAllowsOrDeniesOnlyTheShownInput`.
    #[test]
    fn decide_allows_or_denies_only_the_shown_input() {
        let a = pending_approval();
        let at = approval_t0() + Duration::minutes(1);
        let allowed = ok(a.decide(
            ApprovalDecision {
                allow: true,
                input_mac: a.input_mac,
                decided_by: operator(),
            },
            at,
        ));
        assert_eq!(allowed.state, ApprovalState::Allowed);
        assert_eq!(allowed.decided_by, "operator-session:principal-1");
        assert_eq!(allowed.decided_at, Some(at));
        let denied = ok(a.decide(
            ApprovalDecision {
                allow: false,
                input_mac: a.input_mac,
                decided_by: operator(),
            },
            at,
        ));
        assert_eq!(denied.state, ApprovalState::Denied);
        let other = ok(compute_input_mac(
            test_mac_key(),
            br#"{"command":"rm -rf /"}"#,
        ));
        for allow in [true, false] {
            let err = a
                .decide(
                    ApprovalDecision {
                        allow,
                        input_mac: other,
                        decided_by: operator(),
                    },
                    at,
                )
                .unwrap_err();
            assert!(
                is_code(&err, codes::INPUT_MAC_MISMATCH),
                "allow={allow} of another input: {err}"
            );
        }
        for decider in [
            "",
            "policy:timeout",
            "operator-session:",
            "system:superseded",
            "operator-session:\x1b[31m",
            "operator-session:al\nice",
        ] {
            let err = a
                .decide(
                    ApprovalDecision {
                        allow: true,
                        input_mac: a.input_mac,
                        decided_by: decider.to_string(),
                    },
                    at,
                )
                .unwrap_err();
            assert!(
                is_code(&err, codes::INVALID_APPROVAL),
                "decider {decider:?}: {err}"
            );
        }
        let err = a
            .decide(
                ApprovalDecision {
                    allow: true,
                    input_mac: a.input_mac,
                    decided_by: operator(),
                },
                a.expires_at,
            )
            .unwrap_err();
        assert!(
            is_code(&err, codes::APPROVAL_NOT_PENDING),
            "decision at expiry: {err}"
        );
    }

    // Ports upstream `TestExpireAnswersDenyByTimeoutOnlyOnceDue`.
    #[test]
    fn expire_answers_deny_by_timeout_only_once_due() {
        let a = pending_approval();
        let err = a.expire(a.expires_at - Duration::seconds(1)).unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_APPROVAL),
            "early expiry: {err}"
        );
        let expired = ok(a.expire(a.expires_at));
        assert_eq!(expired.state, ApprovalState::Expired);
        assert_eq!(expired.decided_by, DECIDED_BY_TIMEOUT);
        assert!(!expired.state.allows());
    }

    // Ports upstream `TestSupersedeClosesAPendingApprovalBySystem`.
    #[test]
    fn supersede_closes_a_pending_approval_by_system() {
        let a = pending_approval();
        let s = ok(a.supersede(approval_t0() + Duration::seconds(1)));
        assert_eq!(s.state, ApprovalState::Superseded);
        assert_eq!(s.decided_by, DECIDED_BY_SUPERSEDED);
    }

    // Ports upstream `TestEveryTerminalApprovalStateIsFinal`.
    #[test]
    fn every_terminal_approval_state_is_final() {
        let a = pending_approval();
        let at = approval_t0() + Duration::minutes(1);
        let finals = [
            ok(a.decide(
                ApprovalDecision {
                    allow: true,
                    input_mac: a.input_mac,
                    decided_by: operator(),
                },
                at,
            )),
            ok(a.decide(
                ApprovalDecision {
                    allow: false,
                    input_mac: a.input_mac,
                    decided_by: operator(),
                },
                at,
            )),
            ok(a.expire(a.expires_at)),
            ok(a.supersede(at)),
        ];
        for final_approval in finals {
            assert!(final_approval.state.is_terminal());
            let later = a.expires_at + Duration::hours(1);
            let err = final_approval
                .decide(
                    ApprovalDecision {
                        allow: true,
                        input_mac: a.input_mac,
                        decided_by: operator(),
                    },
                    at,
                )
                .unwrap_err();
            assert!(
                is_code(&err, codes::APPROVAL_NOT_PENDING),
                "{} -> decide: {err}",
                final_approval.state
            );
            let err = final_approval.expire(later).unwrap_err();
            assert!(
                is_code(&err, codes::APPROVAL_NOT_PENDING),
                "{} -> expire: {err}",
                final_approval.state
            );
            let err = final_approval.supersede(later).unwrap_err();
            assert!(
                is_code(&err, codes::APPROVAL_NOT_PENDING),
                "{} -> supersede: {err}",
                final_approval.state
            );
        }
    }

    // Ports upstream `TestApprovalValidateTiesTheDeciderToTheState`.
    #[test]
    fn approval_validate_ties_the_decider_to_the_state() {
        let a = pending_approval();
        let allowed = ok(a.decide(
            ApprovalDecision {
                allow: true,
                input_mac: a.input_mac,
                decided_by: operator(),
            },
            approval_t0() + Duration::seconds(1),
        ));
        let broken = |b: &PermissionApproval, mutate: &dyn Fn(&mut PermissionApproval)| {
            let mut b = b.clone();
            mutate(&mut b);
            b
        };
        let mutations: [(&str, PermissionApproval); 8] = [
            (
                "pending with a decider",
                broken(&a, &|b| b.decided_by = "x".to_string()),
            ),
            (
                "allowed by the timeout",
                broken(&allowed, &|b| b.decided_by = DECIDED_BY_TIMEOUT.to_string()),
            ),
            (
                "expired by an operator",
                broken(&allowed, &|b| b.state = ApprovalState::Expired),
            ),
            (
                "superseded by an operator",
                broken(&allowed, &|b| b.state = ApprovalState::Superseded),
            ),
            (
                "allowed without a time",
                broken(&allowed, &|b| b.decided_at = None),
            ),
            (
                "decided before requested",
                broken(&allowed, &|b| {
                    b.decided_at = Some(approval_t0() - Duration::seconds(1))
                }),
            ),
            ("negative version", broken(&a, &|b| b.version = -1)),
            (
                "allowed by a non-printable operator",
                broken(&allowed, &|b| {
                    b.decided_by = "operator-session:\x1b[31m".to_string()
                }),
            ),
        ];
        for (name, broken) in mutations {
            let err = broken.validate().unwrap_err();
            assert!(
                is_code(&err, codes::INVALID_APPROVAL),
                "{name}: err = {err}"
            );
        }
    }

    // Ports upstream `TestOperatorDeciderIsBoundedPrintableASCII`.
    #[test]
    fn operator_decider_is_bounded_printable_ascii() {
        let d = ok(operator_decider("alice"));
        assert_eq!(d, "operator-session:alice");
        assert!(is_operator_decider(&d));
        for bad in [
            "",
            "al\nice",
            "al\x00ice",
            &"p".repeat(MAX_DECIDED_BY_BYTES),
            "ålice",
        ] {
            let err = operator_decider(bad).unwrap_err();
            assert!(
                is_code(&err, codes::INVALID_APPROVAL),
                "operator_decider({bad:?}): {err}"
            );
        }
        for not_operator in [
            DECIDED_BY_TIMEOUT,
            DECIDED_BY_SUPERSEDED,
            DECIDED_BY_INPUT_TOO_LARGE,
            "operator-session:",
            "operator-session:\x1b[31m",
            "operator-session:ålice",
        ] {
            assert!(
                !is_operator_decider(not_operator),
                "{not_operator:?} counted as an operator"
            );
        }
    }

    // Ports upstream `TestInputMACIsKeyedAndRoundTrips`.
    #[test]
    fn input_mac_is_keyed_and_round_trips() {
        let input = br#"{"command":"echo $TOKEN"}"#;
        let a = ok(compute_input_mac(test_mac_key(), input));
        let b = ok(compute_input_mac(
            b"fedcba9876543210fedcba9876543210",
            input,
        ));
        assert!(
            !a.equal(&b),
            "the MAC does not depend on the key: a plain hash is a guess-confirmation oracle"
        );
        let again = ok(compute_input_mac(test_mac_key(), input));
        assert!(a.equal(&again));
        assert!(!a.is_zero());
        let err = compute_input_mac(b"short", input).unwrap_err();
        assert!(is_code(&err, codes::INVALID_APPROVAL), "short key: {err}");
        let parsed = ok(parse_input_mac(&a.to_string()));
        assert_eq!(parsed, a);
        assert_eq!(a.to_string().len(), 64);
        let bad_forms = [
            String::new(),
            format!("zz{}", &a.to_string()[2..]),
            a.to_string()[..63].to_string(),
            format!("{}0", a),
        ];
        for bad in bad_forms {
            let err = parse_input_mac(&bad).unwrap_err();
            assert!(
                is_code(&err, codes::INVALID_APPROVAL),
                "parse_input_mac({bad:?}): {err}"
            );
        }
    }
}
