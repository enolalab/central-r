//! `AdvisoryAdmissionVerifier` — the port of upstream `admission.go`.
//!
//! It answers the state machine's two admission questions — "may these
//! inputs be used" before the builds, and "may this candidate be promoted"
//! immediately before the selector switch — by actually re-evaluating the
//! advisory, and refuses on anything that is not `current`. The design spec
//! makes this the barrier that blocks promotion on changed policy, so it has
//! to be the real evaluation, never a function whose body is "yes".
//!
//! It deliberately does NOT require the fresh evaluation to return the same
//! receipt ID the operation started with: each evaluation records a new
//! authority-transition receipt, so those IDs differ by construction and
//! comparing them would refuse every prepare. The binding names the FRESH
//! admission — the evaluation that actually authorised this transition — and
//! the operation's original admission survives as lineage in the journalled
//! operation.

use std::sync::Arc;

use central_foundation::failure::Failure;
use central_infra::domain::{AdmissionBinding, new_admission_binding, sha256_prefixed};

use super::OpDeadline;
use super::state_machine::AdmissionVerifier;
use crate::helper::prepare::{ADVISORY_STATE_CURRENT, AdvisoryAdmission, EvaluateService};

const NOT_CURRENT: &str = "ADMISSION_NOT_CURRENT";

fn not_current(detail: impl std::fmt::Display) -> Failure {
    Failure::denied(
        NOT_CURRENT,
        format!("dependencyprepare: advisory admission is not current: {detail}"),
    )
}

/// An evaluator shared between the helper handler (which evaluates before
/// the PAM ceremony) and this verifier — deliberately the same evaluator, so
/// a prepare cannot be admitted by a weaker authority than the one that let
/// the request through the door.
#[derive(Clone)]
pub struct SharedEvaluate(pub Arc<dyn EvaluateService>);

impl EvaluateService for SharedEvaluate {
    fn evaluate(
        &self,
    ) -> Result<(crate::helper::prepare::AdvisoryResult, AdvisoryAdmission), Failure> {
        self.0.evaluate()
    }
}

/// `AdvisoryAdmissionVerifier`.
pub struct AdvisoryAdmissionVerifier {
    eval: Arc<dyn EvaluateService>,
}

impl AdvisoryAdmissionVerifier {
    /// `NewAdvisoryAdmissionVerifier`.
    #[must_use]
    pub fn new(eval: Arc<dyn EvaluateService>) -> Self {
        Self { eval }
    }
}

impl AdmissionVerifier for AdvisoryAdmissionVerifier {
    fn verify_current(
        &self,
        _deadline: OpDeadline,
        admission: &AdvisoryAdmission,
    ) -> Result<AdmissionBinding, Failure> {
        if admission.receipt_id.is_empty() {
            return Err(not_current("operation carries no admission"));
        }
        let (result, fresh) = self
            .eval
            .evaluate()
            .map_err(|e| not_current(format!("evaluation unavailable: {}", e.message())))?;
        if result.state != ADVISORY_STATE_CURRENT {
            return Err(not_current(format!(
                "advisory state {} ({})",
                result.state, result.code
            )));
        }
        if fresh.receipt_id.is_empty() {
            return Err(not_current(
                "current evaluation issued no admission receipt",
            ));
        }
        // The selector token is minted by the caller at promotion time against
        // the selector actually being switched. The token here binds the
        // admission to itself so a binding can never be mistaken for authority
        // over a selector it was not taken for.
        new_admission_binding(
            &fresh.receipt_id,
            &sha256_prefixed(fresh.receipt_id.as_bytes()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::prepare::AdvisoryResult;

    struct Eval(Result<(&'static str, &'static str, &'static str), &'static str>);

    impl EvaluateService for Eval {
        fn evaluate(&self) -> Result<(AdvisoryResult, AdvisoryAdmission), Failure> {
            match self.0 {
                Ok((state, code, receipt)) => Ok((
                    AdvisoryResult {
                        state: state.to_owned(),
                        code: code.to_owned(),
                    },
                    AdvisoryAdmission {
                        receipt_id: receipt.to_owned(),
                    },
                )),
                Err(e) => Err(Failure::internal("EVAL", e)),
            }
        }
    }

    fn verify(eval: Eval, op_admission: &str) -> Result<AdmissionBinding, Failure> {
        AdvisoryAdmissionVerifier::new(Arc::new(eval)).verify_current(
            OpDeadline::NONE,
            &AdvisoryAdmission {
                receipt_id: op_admission.to_owned(),
            },
        )
    }

    #[test]
    fn a_current_evaluation_binds_the_fresh_receipt_not_the_original() {
        let b = verify(Eval(Ok(("current", "", "fresh-2"))), "orig-1").expect("admit");
        assert_eq!(b.admission_receipt_id, "fresh-2");
        assert!(!b.selector_token.is_empty());
    }

    #[test]
    fn anything_but_current_is_refused() {
        for state in ["denied", "expired", "emergency_deny", ""] {
            let err = verify(Eval(Ok((state, "X", "r"))), "orig").expect_err(state);
            assert_eq!(err.code(), NOT_CURRENT, "{state}");
        }
        assert!(verify(Eval(Err("boom")), "orig").is_err());
        assert!(verify(Eval(Ok(("current", "", ""))), "orig").is_err());
        assert!(verify(Eval(Ok(("current", "", "r"))), "").is_err());
    }
}
