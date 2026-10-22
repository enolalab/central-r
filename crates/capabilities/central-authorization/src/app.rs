//! Authorization Service — orchestration only
//! (rust-application-boundaries.md §2.2).
//!
//! Every command loads the durable record through [`crate::port`],
//! evaluates a pure [`crate::domain`] decision, and commits the guarded
//! change set. Policy evaluation itself is synchronous and runs here
//! without any port call — the domain needs only the request and the
//! caller-supplied [`PolicyFacts`]. No transaction is opened here; the
//! adapter owns atomicity.
//!
//! Authority: the service trusts the caller-supplied actor/authority
//! identities — the transport's authenticated-session decision happens
//! before invocation (§7.5). It never fabricates or re-derives them.

use central_foundation::failure::Failure;
use central_foundation::identity::{ApprovalId, OperationId, WorkspaceId};
use time::OffsetDateTime;

use crate::domain::{
    self, ApprovalRecord, AuthorizationRequest, GenesisReceipt, GenesisStatus, InstanceBinding,
    PolicyDecision, PolicyFacts, RestoreSuspension, SecretUseEvidence,
};
use crate::port::{ApprovalStore, GenesisStore, SecretUseEvidenceLog};
use crate::query::{ApprovalSummaryPage, ApprovalSummaryRead, ApprovalSummaryRequest};

/// The resolution applied to one capability-grant approval record
/// (command C7 `ResolveApproval`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalResolution {
    /// `active`/`suspended` → `revoked` (terminal), with a new reason.
    Revoke {
        /// Auditable revocation reason.
        reason: String,
    },
    /// `active` → `suspended` with a mandatory suspend reason.
    Suspend {
        /// Why the grant is suspended.
        suspend_reason: String,
    },
    /// `active`/`suspended` → `expired` (terminal), only when due.
    Expire,
}

/// The authorization capability Service.
pub struct AuthorizationService<S, E, G, R>
where
    S: ApprovalStore,
    E: SecretUseEvidenceLog,
    G: GenesisStore,
    R: ApprovalSummaryRead,
{
    store: S,
    evidence: E,
    genesis: G,
    summary: R,
}

impl<S, E, G, R> AuthorizationService<S, E, G, R>
where
    S: ApprovalStore,
    E: SecretUseEvidenceLog,
    G: GenesisStore,
    R: ApprovalSummaryRead,
{
    /// Wires the service against its ports.
    pub const fn new(store: S, evidence: E, genesis: G, summary: R) -> Self {
        Self {
            store,
            evidence,
            genesis,
            summary,
        }
    }

    /// Evaluates one canonical authorization request against the
    /// Phase-1 policy matrix. Pure — the caller supplies [`PolicyFacts`]
    /// gathered from installed policy, protected configuration, and
    /// registered resources.
    pub fn evaluate_policy(
        &self,
        request: &AuthorizationRequest,
        facts: &PolicyFacts,
    ) -> Result<PolicyDecision, Failure> {
        request.validate()?;
        Ok(domain::evaluate(request, facts))
    }

    /// Establishes a new capability-grant approval record (`action =
    /// grant`, `state = active`). The grant's expiry is validated by
    /// the domain: never beyond the 24-hour task-grant ceiling.
    pub async fn record_grant(
        &self,
        request: domain::GrantRequest,
    ) -> Result<ApprovalRecord, Failure> {
        let record = ApprovalRecord::grant(request)?;
        self.store.insert_approval(record.clone()).await?;
        Ok(record)
    }

    /// Applies a durable resolution to one approval record: load →
    /// domain transition → guarded commit. Terminal records fail with
    /// `conflict`; stale rows fail on the version guard inside the
    /// commit port.
    pub async fn resolve_approval(
        &self,
        workspace_id: WorkspaceId,
        approval_id: ApprovalId,
        resolution: ApprovalResolution,
        now: OffsetDateTime,
    ) -> Result<ApprovalRecord, Failure> {
        let record = self.store.load_approval(workspace_id, approval_id).await?;
        let change_set = match resolution {
            ApprovalResolution::Revoke { reason } => record.evaluate_revocation(reason, now)?,
            ApprovalResolution::Suspend { suspend_reason } => {
                record.evaluate_suspension(suspend_reason, now)?
            }
            ApprovalResolution::Expire => record.evaluate_expiry(now)?,
        };
        self.store
            .commit_approval_change_set(change_set.clone())
            .await?;
        Ok(change_set.next)
    }

    /// The post-restore authority reset: suspends every `active`
    /// capability grant in the Workspace with
    /// `restore_review_required`. Returns the number suspended.
    /// Non-active rows are untouched; each commit runs under its own
    /// version guard so a concurrent decision cannot be clobbered.
    pub async fn reset_authority_for_restore(
        &self,
        workspace_id: WorkspaceId,
        now: OffsetDateTime,
    ) -> Result<usize, Failure> {
        let records = self.store.load_workspace_approvals(workspace_id).await?;
        let mut suspended = 0usize;
        for record in records {
            if let RestoreSuspension::ChangeSet(change_set) =
                record.evaluate_restore_suspension(now)?
            {
                self.store.commit_approval_change_set(*change_set).await?;
                suspended += 1;
            }
        }
        Ok(suspended)
    }

    /// Appends durable `secret_use` audit evidence — the reference
    /// identity and authorization context only, never a secret value.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_secret_use(
        &self,
        workspace_id: WorkspaceId,
        secret_reference_id: impl Into<String>,
        actor_identity: impl Into<String>,
        operation_identity: impl Into<String>,
        authorization_outcome: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<SecretUseEvidence, Failure> {
        let evidence = SecretUseEvidence::record(
            workspace_id,
            secret_reference_id,
            actor_identity,
            operation_identity,
            authorization_outcome,
            now,
        )?;
        self.evidence.append_secret_use(evidence.clone()).await?;
        Ok(evidence)
    }

    /// The bounded Q5 summary read.
    pub async fn approval_summary(
        &self,
        request: &ApprovalSummaryRequest,
    ) -> Result<ApprovalSummaryPage, Failure> {
        request.validate()?;
        self.summary.read_page(request).await
    }

    // -- genesis ------------------------------------------------------------

    /// Loads the durable instance binding, if genesis has bound this
    /// host.
    pub async fn instance_binding(&self) -> Result<Option<InstanceBinding>, Failure> {
        self.genesis.load_instance_binding().await
    }

    /// Persists a domain-validated instance binding.
    pub async fn bind_instance(&self, binding: InstanceBinding) -> Result<(), Failure> {
        binding.validate()?;
        self.genesis.store_instance_binding(binding).await
    }

    /// Loads the genesis status of one operation — phase plus receipt.
    pub async fn genesis_status(
        &self,
        operation_id: OperationId,
    ) -> Result<GenesisStatus, Failure> {
        let status = self.genesis.load_genesis_status(operation_id).await?;
        status.validate()?;
        Ok(status)
    }

    /// Commits a genesis receipt after domain validation.
    pub async fn commit_genesis(&self, receipt: GenesisReceipt) -> Result<(), Failure> {
        receipt.uidgid.validate()?;
        self.genesis.commit_genesis_receipt(receipt).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;
    use crate::domain::{
        ApprovalAction, ApprovalState, Capability, CapabilityScope, Effect, ResourceClass,
        UidGidMap,
    };
    use crate::query::ApprovalSummary;
    use central_foundation::failure::FailureKind;
    use central_foundation::identity::{ConfigBindingId, InstanceId, TaskId};

    const T0: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let waker = core::task::Waker::noop();
        let mut cx = core::task::Context::from_waker(waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                core::task::Poll::Ready(v) => return v,
                core::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Default)]
    struct StubStore {
        rows: Mutex<BTreeMap<ApprovalId, ApprovalRecord>>,
    }

    impl ApprovalStore for StubStore {
        async fn load_approval(
            &self,
            _workspace_id: WorkspaceId,
            approval_id: ApprovalId,
        ) -> Result<ApprovalRecord, Failure> {
            self.rows
                .lock()
                .unwrap()
                .get(&approval_id)
                .cloned()
                .ok_or_else(|| {
                    Failure::not_found(crate::domain::codes::APPROVAL_NOT_FOUND, "missing approval")
                })
        }

        async fn commit_approval_change_set(
            &self,
            change_set: crate::domain::ApprovalChangeSet,
        ) -> Result<(), Failure> {
            let mut rows = self.rows.lock().unwrap();
            let current = rows.get(&change_set.next.id).ok_or_else(|| {
                Failure::not_found(crate::domain::codes::APPROVAL_NOT_FOUND, "missing")
            })?;
            if current.version != change_set.expected_version {
                return Err(Failure::conflict("approval_version_conflict", "stale row"));
            }
            rows.insert(change_set.next.id, change_set.next);
            Ok(())
        }

        async fn insert_approval(&self, record: ApprovalRecord) -> Result<(), Failure> {
            let mut rows = self.rows.lock().unwrap();
            if rows.contains_key(&record.id) {
                return Err(Failure::conflict("approval_exists", "duplicate"));
            }
            rows.insert(record.id, record);
            Ok(())
        }

        async fn load_workspace_approvals(
            &self,
            workspace_id: WorkspaceId,
        ) -> Result<Vec<ApprovalRecord>, Failure> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .values()
                .filter(|r| r.workspace_id == workspace_id)
                .cloned()
                .collect())
        }
    }

    #[derive(Default)]
    struct StubEvidence {
        rows: Mutex<Vec<SecretUseEvidence>>,
    }

    impl SecretUseEvidenceLog for StubEvidence {
        async fn append_secret_use(&self, evidence: SecretUseEvidence) -> Result<(), Failure> {
            self.rows.lock().unwrap().push(evidence);
            Ok(())
        }
    }

    struct StubGenesis;

    impl GenesisStore for StubGenesis {
        async fn load_instance_binding(&self) -> Result<Option<InstanceBinding>, Failure> {
            Ok(None)
        }
        async fn store_instance_binding(&self, _binding: InstanceBinding) -> Result<(), Failure> {
            Ok(())
        }
        async fn load_genesis_status(
            &self,
            operation_id: OperationId,
        ) -> Result<GenesisStatus, Failure> {
            Ok(GenesisStatus {
                operation_id,
                phase: crate::domain::GenesisPhase::Absent,
                receipt: None,
            })
        }
        async fn commit_genesis_receipt(&self, _receipt: GenesisReceipt) -> Result<(), Failure> {
            Ok(())
        }
    }

    struct StubSummary;

    impl ApprovalSummaryRead for StubSummary {
        async fn read_page(
            &self,
            _request: &ApprovalSummaryRequest,
        ) -> Result<ApprovalSummaryPage, Failure> {
            Ok(ApprovalSummaryPage {
                approvals: Vec::<ApprovalSummary>::new(),
                next_cursor: None,
            })
        }
    }

    fn service() -> AuthorizationService<StubStore, StubEvidence, StubGenesis, StubSummary> {
        AuthorizationService::new(
            StubStore::default(),
            StubEvidence::default(),
            StubGenesis,
            StubSummary,
        )
    }

    fn grant(
        svc: &AuthorizationService<StubStore, StubEvidence, StubGenesis, StubSummary>,
    ) -> ApprovalRecord {
        block_on(svc.record_grant(domain::GrantRequest {
            workspace_id: WorkspaceId::new(),
            capability: Capability::new(ResourceClass::Filesystem, Effect::Modify).unwrap(),
            scope: CapabilityScope {
                task_id: Some(TaskId::new()),
                operation_key: None,
                selector: "/work/**".into(),
            },
            actor_identity: "agent:planner".into(),
            authority_identity: "authority:local-console".into(),
            reason: "approved write".into(),
            security_epoch: 1,
            issued_at: T0,
            expiry_at: Some(T0 + time::Duration::hours(2)),
        }))
        .unwrap()
    }

    #[test]
    fn record_grant_inserts_and_resolve_commits_under_version_guard() {
        let svc = service();
        let record = grant(&svc);
        assert_eq!(record.action, ApprovalAction::Grant);
        assert_eq!(record.state, ApprovalState::Active);

        let revoked = block_on(svc.resolve_approval(
            record.workspace_id,
            record.id,
            ApprovalResolution::Revoke {
                reason: "operator withdrew".into(),
            },
            T0 + time::Duration::seconds(5),
        ))
        .unwrap();
        assert_eq!(revoked.state, ApprovalState::Revoked);
        assert_eq!(revoked.version, 1);

        let err = block_on(svc.resolve_approval(
            record.workspace_id,
            record.id,
            ApprovalResolution::Expire,
            T0 + time::Duration::hours(9),
        ))
        .unwrap_err();
        assert_eq!(err.kind(), FailureKind::Conflict);
    }

    #[test]
    fn restore_reset_suspends_only_active_grants() {
        let svc = service();
        let active = grant(&svc);
        let revoked = block_on(svc.resolve_approval(
            active.workspace_id,
            active.id,
            ApprovalResolution::Revoke {
                reason: "done".into(),
            },
            T0,
        ))
        .unwrap();
        let other = grant(&svc);
        // Move `other` to the same workspace as `active` so one reset sees both.
        let mut other_row = other.clone();
        other_row.workspace_id = active.workspace_id;
        svc.store
            .rows
            .lock()
            .unwrap()
            .insert(other_row.id, other_row);

        let n = block_on(svc.reset_authority_for_restore(active.workspace_id, T0)).unwrap();
        assert_eq!(n, 1, "revoked and foreign-workspace rows are untouched");
        let suspended = svc.store.rows.lock().unwrap()[&revoked.id].clone();
        assert_eq!(suspended.state, ApprovalState::Revoked);
    }

    #[test]
    fn secret_use_appends_validated_evidence() {
        let svc = service();
        let evidence = block_on(svc.record_secret_use(
            WorkspaceId::new(),
            "secretref:minio/root",
            "agent",
            "op:1",
            "allow",
            T0,
        ))
        .unwrap();
        assert_eq!(evidence.authorization_outcome, "allow");
        assert_eq!(svc.evidence.rows.lock().unwrap().len(), 1);
    }

    #[test]
    fn genesis_status_validates_before_returning() {
        let svc = service();
        let status = block_on(svc.genesis_status(OperationId::new())).unwrap();
        assert_eq!(status.phase.as_str(), "absent");

        let binding = InstanceBinding {
            instance_id: InstanceId::new(),
            host_id: "a".repeat(64),
            release_digest: "b".repeat(64),
            created_at: T0,
            config_binding_id: ConfigBindingId::new(),
            uidgid: UidGidMap {
                runtime_uid: 501,
                runtime_gid: 501,
                agent_uid: 1001,
                agent_gid: 1001,
                browser_uid: 1002,
                browser_gid: 1002,
            },
        };
        block_on(svc.bind_instance(binding)).unwrap();
    }
}
