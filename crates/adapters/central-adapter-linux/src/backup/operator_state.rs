//! `operatorstate/inspector.go` — the protected-operator-state view
//! for the bound target. The store read is injected
//! ([`ProvisioningRecordReader`]); an absent record projects to
//! `Absent` without error, and only the three settled/initializing
//! record states and four in-flight phases upstream enumerates map —
//! anything else is an error with its best-known projection, exactly
//! as upstream returns `(state, err)` pairs.

#![forbid(unsafe_code)]

use central_backup::domain::{
    ExternalRecordState, ProvisioningPhase, SessionBinding, TargetIdentity,
};
use central_backup::port::{BoxFuture, ProtectedOperatorState, ProtectedOperatorStateInspector};
use central_foundation::failure::Failure;
use uuid::Uuid;

/// `operatorstate.ProvisioningRecordReader` — the record view the
/// inspector is bound to. An absent record must surface as a
/// [`Failure`] whose code is `record_absent`
/// ([`central_backup::app::RECORD_ABSENT_CODE`]).
pub trait ProvisioningRecordReader: Send + Sync {
    /// `ReadProvisioningRecord`.
    fn read_provisioning_record(
        &self,
        target: &TargetIdentity,
    ) -> Result<ProvisioningRecord, Failure>;
}

/// `operatorstate.ProvisioningRecord` — the raw record shape; string
/// state/phase fields are validated by the inspector rather than
/// trusted.
#[derive(Debug, Clone)]
pub struct ProvisioningRecord {
    /// Record target.
    pub target: TargetIdentity,
    /// Operation identity as recorded ("" → nil).
    pub operation_id: String,
    /// External record state (`initializing|ready|absent`).
    pub state: String,
    /// In-flight provisioning phase ("" → none).
    pub phase: String,
    /// Candidate under stage.
    pub candidate_id: String,
    /// Candidate digest.
    pub candidate_digest: String,
    /// Installed baseline digest.
    pub baseline_digest: String,
    /// Epoch-zero marker digests.
    pub epoch_zero_markers: Vec<String>,
    /// Session binding captured when the operation started.
    pub session_binding: SessionBinding,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Record creation instant.
    pub created_at: time::OffsetDateTime,
    /// Last update instant.
    pub updated_at: time::OffsetDateTime,
}

/// `Inspector` — see the module header.
pub struct ProtectedInspector {
    store: Box<dyn ProvisioningRecordReader>,
    target: TargetIdentity,
}

/// `NewInspector` — binds the inspector to its reader and target.
pub fn new_protected_inspector(
    store: Box<dyn ProvisioningRecordReader>,
    target: TargetIdentity,
) -> ProtectedInspector {
    ProtectedInspector { store, target }
}

impl ProtectedInspector {
    fn inspect(&self) -> Result<ProtectedOperatorState, Failure> {
        let detected_at = time::OffsetDateTime::now_utc();
        let record = match self.store.read_provisioning_record(&self.target) {
            Ok(record) => record,
            Err(e) if e.code() == central_backup::app::RECORD_ABSENT_CODE => {
                return Ok(ProtectedOperatorState {
                    record_state: ExternalRecordState::Absent,
                    provisioning_phase: ProvisioningPhase::None,
                    target: self.target.clone(),
                    detected_at: Some(detected_at),
                    ..ProtectedOperatorState::default()
                });
            }
            Err(e) => {
                // Upstream returns `Absent` alongside the error; the
                // Rust result can carry only the refusal.
                return Err(Failure::unavailable(
                    "operator_state",
                    format!("read provisioning record: {}", e.message()),
                ));
            }
        };

        // Upstream's closed state switch: `initializing|ready|absent`
        // map; *every* other value — including applying, verifying,
        // and quarantined, which the wider enum knows — is an unknown
        // record state here, projected as `Initializing`.
        let record_state = match record.state.as_str() {
            "initializing" => ExternalRecordState::Initializing,
            "ready" => ExternalRecordState::Ready,
            "absent" => ExternalRecordState::Absent,
            other => {
                return Err(Failure::unavailable(
                    "operator_state",
                    format!("unknown record state: {other:?}"),
                ));
            }
        };

        let provisioning_phase = match record.phase.as_str() {
            "recorded" => ProvisioningPhase::Recorded,
            "candidate_staged" => ProvisioningPhase::CandidateStaged,
            "baseline_installed" => ProvisioningPhase::BaselineInstalled,
            "candidate_active" => ProvisioningPhase::CandidateActive,
            "" => ProvisioningPhase::None,
            other => {
                return Err(Failure::unavailable(
                    "operator_state",
                    format!("unknown provisioning phase: {other:?}"),
                ));
            }
        };

        // A malformed operation id is ignored, never an error — the
        // record's nil-identity shape is what downstream distinguishes.
        let operation_id = Uuid::parse_str(&record.operation_id).unwrap_or_else(|_| Uuid::nil());

        Ok(ProtectedOperatorState {
            record_state,
            provisioning_phase,
            target: self.target.clone(),
            operation_id,
            revision: record.revision,
            session_binding: record.session_binding.clone(),
            detected_at: Some(detected_at),
        })
    }
}

impl ProtectedOperatorStateInspector for ProtectedInspector {
    /// `Inspect` — the store read is synchronous; the trait's async
    /// seam wraps it so the coordinator boundary stays uniform.
    fn inspect_operator_state<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<ProtectedOperatorState, Failure>> {
        Box::pin(async move { self.inspect() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys-1".into(),
            database_oid: "16639".into(),
            database: "central".into(),
            config_hash: "cfg".into(),
            epoch: 3,
        }
    }

    fn record(state: &str, phase: &str) -> ProvisioningRecord {
        ProvisioningRecord {
            target: target(),
            operation_id: Uuid::now_v7().to_string(),
            state: state.into(),
            phase: phase.into(),
            candidate_id: String::new(),
            candidate_digest: String::new(),
            baseline_digest: String::new(),
            epoch_zero_markers: Vec::new(),
            session_binding: SessionBinding::default(),
            revision: 9,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    struct FakeReader {
        outcome: Mutex<Result<ProvisioningRecord, Failure>>,
    }
    impl ProvisioningRecordReader for FakeReader {
        fn read_provisioning_record(
            &self,
            _target: &TargetIdentity,
        ) -> Result<ProvisioningRecord, Failure> {
            self.outcome.lock().unwrap().clone()
        }
    }

    fn inspector_with(outcome: Result<ProvisioningRecord, Failure>) -> ProtectedInspector {
        new_protected_inspector(
            Box::new(FakeReader {
                outcome: Mutex::new(outcome),
            }),
            target(),
        )
    }

    #[tokio::test]
    async fn absent_record_projects_absent_without_error() {
        let inspector = inspector_with(Err(Failure::not_found(
            central_backup::app::RECORD_ABSENT_CODE,
            "absent",
        )));
        let state = inspector.inspect_operator_state().await.unwrap();
        assert_eq!(state.record_state, ExternalRecordState::Absent);
        assert_eq!(state.provisioning_phase, ProvisioningPhase::None);
        assert!(state.detected_at.is_some());
        assert_eq!(state.target, target());
    }

    #[tokio::test]
    async fn known_states_and_phases_project_verbatim() {
        let inspector = inspector_with(Ok(record("ready", "candidate_active")));
        let state = inspector.inspect_operator_state().await.unwrap();
        assert_eq!(state.record_state, ExternalRecordState::Ready);
        assert_eq!(state.provisioning_phase, ProvisioningPhase::CandidateActive);
        assert_eq!(state.revision, 9);
        assert!(!state.operation_id.is_nil());

        let inspector = inspector_with(Ok(record("initializing", "recorded")));
        let state = inspector.inspect_operator_state().await.unwrap();
        assert_eq!(state.record_state, ExternalRecordState::Initializing);
        assert_eq!(state.provisioning_phase, ProvisioningPhase::Recorded);
    }

    #[tokio::test]
    async fn unknown_states_phases_and_store_failures_refuse() {
        // A record state the inspector does not enumerate refuses —
        // including enum-known states outside its closed set.
        for bad in ["applying", "verifying", "quarantined", "bogus"] {
            let inspector = inspector_with(Ok(record(bad, "recorded")));
            assert!(inspector.inspect_operator_state().await.is_err());
        }
        // An unknown phase refuses.
        let inspector = inspector_with(Ok(record("ready", "bogus")));
        assert!(inspector.inspect_operator_state().await.is_err());
        // A store failure (non-absent) refuses.
        let inspector = inspector_with(Err(Failure::unavailable("store", "connection lost")));
        assert!(inspector.inspect_operator_state().await.is_err());
    }
}
