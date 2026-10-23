//! Vocabularies and small value types shared across the harness domain —
//! the port of `internal/harness/domain.go`. Everything here is pure and
//! synchronous; the only imports are `central-foundation` and `time`.
//!
//! The Go package's sentinel errors (`ErrInvalidTransition`,
//! `ErrFenceMismatch`, `ErrInvalidAttempt`, `ErrSessionMismatch`,
//! `ErrPermissionMismatch`, `ErrResumeNotAllowed`,
//! `ErrForbiddenLaunchEnv`, `ErrInvalidEvent`, `ErrInvalidCapabilities`,
//! the approval sentinels, `ErrChainBudgetExhausted` and the persistence
//! sentinels a store maps driver failures onto) travel here as
//! [`Failure`]s carrying the stable machine codes in [`codes`] — the
//! `errors.Is` surface a caller matches on.

use std::fmt;

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::macros::datetime;

/// The Go zero `time.Time` — `0001-01-01T00:00:00Z`. Guards and
/// validators reject it exactly as upstream rejects `t.IsZero()`.
pub const ZERO_TIME: OffsetDateTime = datetime!(0001-01-01 00:00:00 UTC);

/// Reports whether `t` is the Go zero time — `t.IsZero()`.
#[must_use]
pub fn is_zero_time(t: OffsetDateTime) -> bool {
    t == ZERO_TIME
}

/// Stable machine codes standing in for the upstream `errors.Is`
/// sentinels. A `Failure`'s `code()` is what callers match.
pub mod codes {
    /// `harness.ErrInvalidTransition`.
    pub const INVALID_TRANSITION: &str = "harness_invalid_transition";
    /// `harness.ErrFenceMismatch`.
    pub const FENCE_MISMATCH: &str = "harness_fence_mismatch";
    /// `harness.ErrInvalidAttempt`.
    pub const INVALID_ATTEMPT: &str = "harness_invalid_attempt";
    /// `harness.ErrSessionMismatch`.
    pub const SESSION_MISMATCH: &str = "harness_session_mismatch";
    /// `harness.ErrPermissionMismatch`.
    pub const PERMISSION_MISMATCH: &str = "harness_permission_mismatch";
    /// `harness.ErrResumeNotAllowed`.
    pub const RESUME_NOT_ALLOWED: &str = "harness_resume_not_allowed";
    /// `harness.ErrForbiddenLaunchEnv`.
    pub const FORBIDDEN_LAUNCH_ENV: &str = "harness_forbidden_launch_env";
    /// `harness.ErrInvalidEvent`.
    pub const INVALID_EVENT: &str = "harness_invalid_event";
    /// `harness.ErrInvalidCapabilities`.
    pub const INVALID_CAPABILITIES: &str = "harness_invalid_capabilities";
    /// `harness.ErrInvalidApproval`.
    pub const INVALID_APPROVAL: &str = "harness_invalid_approval";
    /// `harness.ErrApprovalNotPending`.
    pub const APPROVAL_NOT_PENDING: &str = "harness_approval_not_pending";
    /// `harness.ErrInputMACMismatch`.
    pub const INPUT_MAC_MISMATCH: &str = "harness_input_mac_mismatch";
    /// `harness.ErrNoPendingApproval`.
    pub const NO_PENDING_APPROVAL: &str = "harness_no_pending_approval";
    /// `harness.ErrChainBudgetExhausted`.
    pub const CHAIN_BUDGET_EXHAUSTED: &str = "harness_chain_budget_exhausted";
    /// `harness.ErrRecoveryNotAuthorized`.
    pub const RECOVERY_NOT_AUTHORIZED: &str = "harness_recovery_not_authorized";
    /// `harness.ErrAttemptNotFound` — a persistence sentinel the domain
    /// owns so a store adapter maps driver failures onto it and no driver
    /// type crosses the port.
    pub const ATTEMPT_NOT_FOUND: &str = "harness_attempt_not_found";
    /// `harness.ErrVersionConflict` — persistence sentinel.
    pub const VERSION_CONFLICT: &str = "harness_version_conflict";
    /// `harness.ErrLiveAttemptExists` — persistence sentinel.
    pub const LIVE_ATTEMPT_EXISTS: &str = "harness_live_attempt_exists";
    /// `harness.ErrEventConflict` — persistence sentinel.
    pub const EVENT_CONFLICT: &str = "harness_event_conflict";
}

/// Builds a closed-vocabulary enum standing in for an upstream Go
/// `type X string` plus its constants, `Xs()` enumerator and `Known()`.
///
/// The generated type is `Copy` and fieldless: `Unset` stands for the Go
/// zero value `""`, `Unknown` for any undeclared text. `parse` — like the
/// upstream conversion `X(s)` — is total and lossy for undeclared text
/// (validation rejects it before persistence, so the dropped spelling
/// never crosses a wire). Serialize/Deserialize use the declared string
/// form: `Unset` is `""`, as the upstream column values are.
macro_rules! vocab {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $text:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub enum $name {
            /// The Go zero value `""`.
            #[default]
            Unset,
            $( $(#[$vmeta])* $variant, )+
            /// Any undeclared text — never [`known`](Self::known).
            Unknown,
        }

        impl $name {
            /// Every declared value in declaration order — upstream's
            /// `Xs()` enumerator.
            pub const ALL: &[Self] = &[ $( Self::$variant ),+ ];

            /// Every declared value in declaration order.
            #[must_use]
            pub fn all() -> &'static [Self] {
                Self::ALL
            }

            /// The declared wire text; `""` for `Unset`, the upstream
            /// zero-value spelling.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    Self::Unset => "",
                    $( Self::$variant => $text, )+
                    Self::Unknown => "",
                }
            }

            /// `true` exactly for a declared value — upstream `Known()`.
            #[must_use]
            pub const fn known(self) -> bool {
                !matches!(self, Self::Unset | Self::Unknown)
            }

            /// The upstream `X(s)` conversion: `""` maps to `Unset`, a
            /// declared spelling to its variant, anything else to
            /// `Unknown`.
            #[must_use]
            pub fn parse(s: &str) -> Self {
                match s {
                    "" => Self::Unset,
                    $( $text => Self::$variant, )+
                    _ => Self::Unknown,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(
                &self,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Ok(Self::parse(&<String as serde::Deserialize>::deserialize(d)?))
            }
        }
    };
}

pub(crate) use vocab;

vocab! {
    /// The lifecycle state of one harness session attempt — upstream
    /// `State` and its `State*` constants.
    State {
        /// `prepared`.
        Prepared => "prepared",
        /// `launching`.
        Launching => "launching",
        /// `running`.
        Running => "running",
        /// `awaiting_permission`.
        AwaitingPermission => "awaiting_permission",
        /// `ambiguous`.
        Ambiguous => "ambiguous",
        /// `succeeded`.
        Succeeded => "succeeded",
        /// `failed`.
        Failed => "failed",
        /// `interrupted`.
        Interrupted => "interrupted",
        /// `killed`.
        Killed => "killed",
        /// `budget_exhausted`.
        BudgetExhausted => "budget_exhausted",
        /// `resolved`.
        Resolved => "resolved",
    }
}

impl State {
    /// Upstream `IsTerminal`: `true` when the state has no outgoing
    /// transitions.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Interrupted
                | Self::Killed
                | Self::BudgetExhausted
                | Self::Resolved
        )
    }

    /// Upstream `ValidTransitions`: the legal next states, or `[]` for a
    /// terminal, unset or unknown state.
    #[must_use]
    pub fn valid_transitions(self) -> &'static [Self] {
        match self {
            Self::Prepared => &[Self::Launching, Self::Failed, Self::Ambiguous],
            Self::Launching => &[
                Self::Running,
                Self::Failed,
                Self::Interrupted,
                Self::Killed,
                Self::Ambiguous,
            ],
            Self::Running => &[
                Self::AwaitingPermission,
                Self::Succeeded,
                Self::Failed,
                Self::Interrupted,
                Self::Killed,
                Self::BudgetExhausted,
                Self::Ambiguous,
            ],
            Self::AwaitingPermission => &[
                Self::Running,
                Self::Failed,
                Self::Interrupted,
                Self::Killed,
                Self::BudgetExhausted,
                Self::Ambiguous,
            ],
            Self::Ambiguous => &[Self::Resolved],
            _ => &[],
        }
    }

    /// Upstream `CanTransition`: `true` when `to` is a legal next state.
    #[must_use]
    pub fn can_transition(self, to: Self) -> bool {
        self.valid_transitions().contains(&to)
    }
}

vocab! {
    /// The operator-chosen handling of harness permission requests for
    /// one attempt — upstream `PermissionPolicy`.
    PermissionPolicy {
        /// `deny`.
        Deny => "deny",
        /// `bridge`.
        Bridge => "bridge",
        /// `auto_allow`.
        AutoAllow => "auto_allow",
    }
}

vocab! {
    /// How a harness session ended, as reported by an adapter — upstream
    /// `TerminalStatus`.
    TerminalStatus {
        /// `succeeded`.
        Succeeded => "succeeded",
        /// `failed`.
        Failed => "failed",
        /// `max_turns`.
        MaxTurns => "max_turns",
        /// `interrupted`.
        Interrupted => "interrupted",
        /// `killed`.
        Killed => "killed",
        /// `budget`.
        Budget => "budget",
    }
}

vocab! {
    /// The operator's answer to an ambiguous attempt — upstream
    /// `ResolutionKind`.
    ResolutionKind {
        /// `resume`.
        Resume => "resume",
        /// `rerun`.
        Rerun => "rerun",
        /// `abandon`.
        Abandon => "abandon",
    }
}

/// Identifies a harness adapter — upstream `Kind`, a string of
/// lower-case letters, digits and `-` (`"claude-code"`, `"opencode"`).
/// Construction is unchecked, as upstream's is; [`Kind::validate`]
/// applies the syntax.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Kind(String);

impl Kind {
    /// A kind from its wire spelling; unchecked.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Upstream `Kind.Validate`: a non-empty name of `a-z`, `0-9` and
    /// `-`.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.0.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "empty harness kind",
            ));
        }
        for r in self.0.chars() {
            if !(r.is_ascii_lowercase() || r.is_ascii_digit() || r == '-') {
                return Err(Failure::invalid(
                    codes::INVALID_ATTEMPT,
                    format!("harness kind {:?} must use only a-z, 0-9 and '-'", self.0),
                ));
            }
        }
        Ok(())
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Carries the Run's execution-lease fencing generation — upstream
/// `Fence`. The domain rejects a caller fence that differs from the
/// loaded attempt; it cannot detect a stale in-memory copy, so
/// persistence must compare-and-swap on it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
pub struct Fence {
    /// The lease generation; must be at least 1.
    pub generation: i64,
}

impl Fence {
    /// Upstream `Fence.Validate`: a generation of at least 1.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.generation < 1 {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "fence generation must be >= 1",
            ));
        }
        Ok(())
    }
}

/// The worktree a harness runs in and the commit it started from —
/// upstream `Workspace`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Workspace {
    /// The worktree path.
    pub path: String,
    /// The commit SHA the attempt started from.
    pub base_sha: String,
}

impl Workspace {
    /// Upstream `Workspace.Validate`: both fields required.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.path.is_empty() || self.base_sha.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "workspace path and base SHA are required",
            ));
        }
        Ok(())
    }
}

/// Describes the end of a harness session — upstream `Terminal`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Terminal {
    /// The adapter-reported end status.
    pub status: TerminalStatus,
    /// A short machine or adapter reason; may carry no payload text.
    pub reason: String,
    /// The process exit code when the adapter observed one.
    pub exit_code: Option<i32>,
}

impl Terminal {
    /// Upstream `Terminal.State`: maps a terminal status to the attempt
    /// state it produces.
    pub fn state(&self) -> Result<State, Failure> {
        match self.status {
            TerminalStatus::Succeeded => Ok(State::Succeeded),
            TerminalStatus::Failed | TerminalStatus::MaxTurns => Ok(State::Failed),
            TerminalStatus::Interrupted => Ok(State::Interrupted),
            TerminalStatus::Killed => Ok(State::Killed),
            TerminalStatus::Budget => Ok(State::BudgetExhausted),
            other => Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("unknown terminal status {}", other.as_str()),
            )),
        }
    }

    /// Upstream `Terminal.IsZero`: no terminal recorded.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.status == TerminalStatus::Unset && self.reason.is_empty() && self.exit_code.is_none()
    }
}

/// Records how and by whom an ambiguous attempt was resolved — upstream
/// `Resolution`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Resolution {
    /// The operator's answer.
    pub kind: ResolutionKind,
    /// Who decided — the decider vocabulary lives in
    /// [`crate::approval`].
    pub decided_by: String,
}

impl Resolution {
    /// Upstream `Resolution.Validate`: a known kind and a decider.
    pub fn validate(&self) -> Result<(), Failure> {
        if !matches!(
            self.kind,
            ResolutionKind::Resume | ResolutionKind::Rerun | ResolutionKind::Abandon
        ) {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                format!("unknown resolution {}", self.kind.as_str()),
            ));
        }
        if self.decided_by.is_empty() {
            return Err(Failure::invalid(
                codes::INVALID_ATTEMPT,
                "resolution requires decided_by",
            ));
        }
        Ok(())
    }

    /// Upstream `Resolution.IsZero`: no resolution recorded.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.kind == ResolutionKind::Unset && self.decided_by.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::codes;
    use crate::testkit::is_code;

    // Ports upstream `TestStateTransitionMatrix`.
    #[test]
    fn state_transition_matrix() {
        let allowed: [(State, &[State]); 5] = [
            (
                State::Prepared,
                &[State::Launching, State::Failed, State::Ambiguous],
            ),
            (
                State::Launching,
                &[
                    State::Running,
                    State::Failed,
                    State::Interrupted,
                    State::Killed,
                    State::Ambiguous,
                ],
            ),
            (
                State::Running,
                &[
                    State::AwaitingPermission,
                    State::Succeeded,
                    State::Failed,
                    State::Interrupted,
                    State::Killed,
                    State::BudgetExhausted,
                    State::Ambiguous,
                ],
            ),
            (
                State::AwaitingPermission,
                &[
                    State::Running,
                    State::Failed,
                    State::Interrupted,
                    State::Killed,
                    State::BudgetExhausted,
                    State::Ambiguous,
                ],
            ),
            (State::Ambiguous, &[State::Resolved]),
        ];
        for from in State::all() {
            let want: &[State] = allowed
                .iter()
                .find(|(state, _)| state == from)
                .map_or(&[], |(_, targets)| targets);
            for to in State::all() {
                assert_eq!(
                    from.can_transition(*to),
                    want.contains(to),
                    "{from} -> {to}: can_transition"
                );
            }
            assert_eq!(from.is_terminal(), want.is_empty(), "{from} is_terminal");
        }
        assert!(!State::parse("bogus").known());
    }

    // Ports upstream `TestKindValidate`.
    #[test]
    fn kind_validate() {
        for ok in ["claude-code", "opencode", "opencode2"] {
            assert!(Kind::new(ok).validate().is_ok(), "{ok}");
        }
        for bad in ["", "Claude", "claude_code", "a b"] {
            let err = Kind::new(bad).validate().unwrap_err();
            assert!(is_code(&err, codes::INVALID_ATTEMPT), "{bad}: err = {err}");
        }
    }

    // Ports upstream `TestTerminalStateMapping`.
    #[test]
    fn terminal_state_mapping() {
        let cases: [(TerminalStatus, State); 6] = [
            (TerminalStatus::Succeeded, State::Succeeded),
            (TerminalStatus::Failed, State::Failed),
            (TerminalStatus::MaxTurns, State::Failed),
            (TerminalStatus::Interrupted, State::Interrupted),
            (TerminalStatus::Killed, State::Killed),
            (TerminalStatus::Budget, State::BudgetExhausted),
        ];
        for (status, want) in cases {
            let got = Terminal {
                status,
                ..Terminal::default()
            }
            .state()
            .unwrap();
            assert_eq!(got, want, "{status}");
        }
        for unknown in [
            TerminalStatus::parse("exploded"),
            TerminalStatus::Unset,
            TerminalStatus::Unknown,
        ] {
            let err = Terminal {
                status: unknown,
                ..Terminal::default()
            }
            .state()
            .unwrap_err();
            assert!(is_code(&err, codes::INVALID_ATTEMPT));
        }
    }

    // Ports upstream `TestValueTypeValidation`.
    #[test]
    fn value_type_validation() {
        let err = Fence { generation: 0 }.validate().unwrap_err();
        assert!(is_code(&err, codes::INVALID_ATTEMPT), "zero fence: {err}");
        let err = Workspace {
            path: "/w".to_string(),
            base_sha: String::new(),
        }
        .validate()
        .unwrap_err();
        assert!(is_code(&err, codes::INVALID_ATTEMPT), "no SHA: {err}");
        let err = Resolution {
            kind: ResolutionKind::Resume,
            decided_by: String::new(),
        }
        .validate()
        .unwrap_err();
        assert!(is_code(&err, codes::INVALID_ATTEMPT), "no decider: {err}");
        let err = Resolution {
            kind: ResolutionKind::parse("retry"),
            decided_by: "op".to_string(),
        }
        .validate()
        .unwrap_err();
        assert!(
            is_code(&err, codes::INVALID_ATTEMPT),
            "unknown resolution: {err}"
        );
        assert!(PermissionPolicy::Bridge.known());
        assert!(!PermissionPolicy::parse("ask").known());
    }

    // Ports upstream `TestTerminalStatusesEnumerator`; `all()` is a
    // `&'static` slice so the upstream "mutating the result does not
    // affect the next call" arm is compile-time guaranteed.
    #[test]
    fn terminal_statuses_enumerator() {
        let mut seen = std::collections::BTreeSet::new();
        for status in TerminalStatus::all() {
            assert!(
                Terminal {
                    status: *status,
                    ..Terminal::default()
                }
                .state()
                .is_ok(),
                "{status}: state() refused"
            );
            assert!(seen.insert(*status), "{status}: duplicate");
        }
    }

    // Ports upstream `TestPermissionPoliciesEnumerator`.
    #[test]
    fn permission_policies_enumerator() {
        let mut seen = std::collections::BTreeSet::new();
        for policy in PermissionPolicy::all() {
            assert!(policy.known(), "{policy}: not known");
            assert!(seen.insert(*policy), "{policy}: duplicate");
        }
    }

    // Ports upstream `TestResolutionKindsEnumerator`.
    #[test]
    fn resolution_kinds_enumerator() {
        let mut seen = std::collections::BTreeSet::new();
        for kind in ResolutionKind::all() {
            assert!(
                Resolution {
                    kind: *kind,
                    decided_by: "op".to_string(),
                }
                .validate()
                .is_ok(),
                "{kind}: validate refused"
            );
            assert!(seen.insert(*kind), "{kind}: duplicate");
        }
    }
}
