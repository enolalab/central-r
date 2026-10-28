//! `matrix.go` — the closed operation matrix. `implemented` is enforced
//! by [`crate::helper::server::Server::handle_conn`]; `requires_pam` and
//! `destructive` are documentation, exactly as upstream's `Operation`
//! declares: each handler enforces its own ceremony.
//!
//! R5 task 8 marks implemented only this slice's verbs: `init`, `up`,
//! `down`, `status`, `browser-open`, `bootstrap-show`, plus `prepare`
//! through the conditional-injection arm (its row stays `false`,
//! upstream-fashion); R5 task 9 added the migration pair; R6 task 7
//! adds exactly the seven backup/restore maintenance verbs that have
//! real backing operations: `backup-create`, `backup-verify`,
//! `backup-status`, `restore-verify`, `restore-apply`,
//! `restore-resume`, `restore-abandon`. Every later verb upstream's
//! tree happens to carry as implemented is deliberately `false` here —
//! the slice must deny them with `UNSUPPORTED_IN_THIS_SLICE`, never
//! fake them.

use super::verb;
use std::collections::BTreeMap;

/// One matrix row — upstream `Operation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operation {
    pub verb: &'static str,
    pub implemented: bool,
    pub requires_pam: bool,
    pub destructive: bool,
}

/// The authoritative closed matrix.
pub struct Matrix {
    verbs: BTreeMap<&'static str, Operation>,
}

impl Matrix {
    /// `NewMatrix` — same registrations, same PAM/destructive marks as
    /// upstream; `implemented` narrows to the R5 slice.
    pub fn new() -> Self {
        let mut m = Matrix {
            verbs: BTreeMap::new(),
        };
        let mut register = |verb: &'static str, implemented: bool, pam: bool, dest: bool| {
            m.verbs.insert(
                verb,
                Operation {
                    verb,
                    implemented,
                    requires_pam: pam,
                    destructive: dest,
                },
            );
        };
        register(verb::INIT, true, true, false);
        register(verb::INIT_STATUS, false, false, false);
        register(verb::INIT_RESUME, false, true, false);
        register(verb::INIT_ABANDON, false, true, true);
        // prepare is conditionally implemented through Server::prepare;
        // the row stays `false`, exactly as upstream.
        register(verb::PREPARE, false, true, false);
        register(verb::SECURITY_UPDATE, false, true, false);
        register(verb::TRUST_INSTALL, false, true, false);
        register(verb::BROWSER_OPEN, true, true, false);
        register(verb::RUNTIME_STAGE, false, true, false);
        register(verb::RUNTIME_START, false, true, false);
        register(verb::RUNTIME_STOP, false, true, false);
        register(verb::UP, true, true, false);
        register(verb::DOWN, true, true, false);
        register(verb::STATUS, true, false, false);
        register(verb::DOCTOR, false, false, false);
        register(verb::WIPE, true, true, true);
        register(verb::BOOTSTRAP_SHOW, true, false, false);
        register(verb::SECURITY_RESCUE_CLEANUP, false, true, false);
        register(verb::MIGRATE_LAUNCH, true, true, false);
        register(verb::MIGRATE_READ_OUTCOME, true, false, false);
        register(verb::BACKUP_CREATE, true, true, false);
        register(verb::BACKUP_VERIFY, true, false, false);
        register(verb::BACKUP_STATUS, true, false, false);
        register(verb::RESTORE_VERIFY, true, false, false);
        register(verb::RESTORE_APPLY, true, true, true);
        register(verb::RESTORE_RESUME, true, true, true);
        register(verb::RESTORE_ABANDON, true, true, true);
        register(verb::BACKUP_EXPORT, true, true, false);
        register(verb::BACKUP_IMPORT, true, true, true);
        register(verb::BACKUP_DELETE, true, true, true);
        register(verb::BACKUP_PRUNE, true, true, true);
        register(verb::STATE_AUDIT, false, false, false);
        register(verb::SECURITY_RESCUE, false, true, false);
        register(verb::MAINTENANCE_PLAN, false, false, false);
        register(verb::MAINTENANCE_APPLY, false, true, false);
        m
    }

    /// `Lookup` — unregistered verbs MUST be treated as unsupported.
    pub fn lookup(&self, verb: &str) -> Option<Operation> {
        self.verbs.get(verb).copied()
    }

    /// `Verbs` — every registered verb, sorted; tests iterate this set
    /// rather than a hand-maintained list that could drift.
    pub fn verbs(&self) -> Vec<&'static str> {
        self.verbs.keys().copied().collect()
    }
}

impl Default for Matrix {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::server::helper_verb_deadline;

    /// Upstream `TestEveryImplementedHelperVerbHasAPositiveTransportDeadline`
    /// — every Implemented verb (plus the prepare injection arm) must
    /// carry a positive transport budget, iterated off the matrix's own
    /// registrations.
    #[test]
    fn every_implemented_verb_has_a_positive_transport_deadline() {
        let m = Matrix::new();
        for verb in m.verbs() {
            let op = m.lookup(verb).unwrap();
            if op.implemented {
                assert!(
                    helper_verb_deadline(verb) > std::time::Duration::ZERO,
                    "implemented verb {verb} has no transport deadline"
                );
            }
        }
        assert!(helper_verb_deadline(verb::PREPARE) > std::time::Duration::ZERO);
    }

    /// The closed set: 35 verbs, 18 implemented (R5's eight plus the
    /// conditional prepare arm, the R5T9 migration pair, the seven
    /// R6T7 backup/restore maintenance verbs, and the three R6 Slice D
    /// destructive verbs); the deferred verbs upstream implements are
    /// closed.
    #[test]
    fn matrix_closes_every_later_operation() {
        let m = Matrix::new();
        assert_eq!(m.verbs().len(), 35);
        let implemented: Vec<&str> = m
            .verbs()
            .into_iter()
            .filter(|v| m.lookup(v).map(|op| op.implemented).unwrap_or(false))
            .collect();
        let mut expected = vec![
            verb::INIT,
            verb::UP,
            verb::DOWN,
            verb::STATUS,
            verb::BROWSER_OPEN,
            verb::BOOTSTRAP_SHOW,
            verb::MIGRATE_LAUNCH,
            verb::MIGRATE_READ_OUTCOME,
            verb::BACKUP_CREATE,
            verb::BACKUP_VERIFY,
            verb::BACKUP_STATUS,
            verb::RESTORE_VERIFY,
            verb::RESTORE_APPLY,
            verb::RESTORE_RESUME,
            verb::RESTORE_ABANDON,
            verb::WIPE,
            verb::BACKUP_EXPORT,
            verb::BACKUP_IMPORT,
            verb::BACKUP_DELETE,
            verb::BACKUP_PRUNE,
        ];
        expected.sort_unstable();
        assert_eq!(implemented, expected);
        for deferred in [
            verb::SECURITY_UPDATE,
            verb::SECURITY_RESCUE,
            verb::STATE_AUDIT,
            verb::MAINTENANCE_PLAN,
            verb::MAINTENANCE_APPLY,
        ] {
            assert!(
                !m.lookup(deferred).unwrap().implemented,
                "{deferred} must stay closed"
            );
        }
    }
}
