//! The adapter self-description — the port of
//! `internal/harness/capability.go`. [`Capabilities`] is declared
//! explicitly by every adapter; the zero value of a field means
//! unsupported, and [`Capabilities::validate`] checks consistency at
//! registration.

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};

use crate::domain::codes;
use crate::event::UsageScope;

/// What an adapter declares it can do — upstream `Capabilities`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// Accepts streaming input.
    pub streaming_input: bool,
    /// Supports interruption.
    pub interrupt: bool,
    /// Can resume a session by id.
    pub resume_by_id: bool,
    /// Central chooses the harness session id before launch (Claude
    /// Code's `--session-id`), so the id is known before the process
    /// exists.
    pub preassign_session_id: bool,
    /// Can fork a session.
    pub fork: bool,
    /// Bridges permission requests to the operator.
    pub permission_bridge: bool,
    /// Streams partial deltas.
    pub partial_deltas: bool,
    /// Reports token usage.
    pub usage_tokens: bool,
    /// Reports cost in USD.
    pub cost_usd: bool,
    /// What the reported usage covers; required exactly when usage is
    /// reported.
    pub usage_scope: UsageScope,
    /// Can reattach to a live session.
    pub reattach: bool,
    /// Resumes automatically when the harness restarts.
    pub auto_resume_on_restart: bool,
    /// The harness enforces a cost limit itself (Claude Code's
    /// `--max-budget-usd`), so Central passes `port.Limits`' max cost to
    /// it (harness phase 3d decision 5). An adapter without it refuses a
    /// positive limit.
    pub native_cost_limit: bool,
}

impl Capabilities {
    /// Upstream `Capabilities.Validate`: `usage_scope` exactly when usage
    /// is reported, and a known scope when set.
    pub fn validate(&self) -> Result<(), Failure> {
        let reports = self.usage_tokens || self.cost_usd;
        if reports && self.usage_scope == UsageScope::Unset {
            return Err(Failure::invalid(
                codes::INVALID_CAPABILITIES,
                "usage reported without a usage scope",
            ));
        }
        if !reports && self.usage_scope != UsageScope::Unset {
            return Err(Failure::invalid(
                codes::INVALID_CAPABILITIES,
                "usage scope set but no usage reported",
            ));
        }
        if self.usage_scope != UsageScope::Unset && !self.usage_scope.known() {
            return Err(Failure::invalid(
                codes::INVALID_CAPABILITIES,
                format!("unknown usage scope {}", self.usage_scope.as_str()),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::codes;
    use crate::event::UsageScope;
    use crate::testkit::is_code;

    // Ports upstream `TestCapabilitiesValidate`.
    #[test]
    fn capabilities_validate() {
        let valid = [
            Capabilities::default(),
            Capabilities {
                interrupt: true,
                resume_by_id: true,
                ..Capabilities::default()
            },
            Capabilities {
                resume_by_id: true,
                preassign_session_id: true,
                ..Capabilities::default()
            },
            Capabilities {
                usage_tokens: true,
                usage_scope: UsageScope::Step,
                ..Capabilities::default()
            },
            Capabilities {
                cost_usd: true,
                usage_scope: UsageScope::SessionCumulative,
                ..Capabilities::default()
            },
        ];
        for (i, c) in valid.iter().enumerate() {
            assert!(
                c.validate().is_ok(),
                "valid[{i}]: {}",
                c.validate().unwrap_err()
            );
        }
        let invalid = [
            Capabilities {
                usage_tokens: true,
                ..Capabilities::default()
            },
            Capabilities {
                usage_scope: UsageScope::Run,
                ..Capabilities::default()
            },
            Capabilities {
                cost_usd: true,
                usage_scope: UsageScope::parse("weekly"),
                ..Capabilities::default()
            },
        ];
        for (i, c) in invalid.iter().enumerate() {
            let err = c.validate().unwrap_err();
            assert!(
                is_code(&err, codes::INVALID_CAPABILITIES),
                "invalid[{i}]: err = {err}"
            );
        }
    }
}
