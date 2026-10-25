//! The `central-infra` application layer — thin orchestration over
//! `domain` through `port` boundaries, mirroring upstream
//! `internal/authority/app/genesis_service.go`.
//!
//! [`GenesisService`] is deliberately a skeleton, like upstream: it
//! composes [`crate::port::GenesisPort`] (durable genesis records) and
//! [`crate::port::HelperClient`] (the privileged helper socket), and
//! today it answers `status` from the durable record alone and passes
//! helper verbs through unmodified. The actual genesis ceremony —
//! `init`, `init-resume`, `init-abandon` state transitions — lands
//! with its owning R5 task (T13+); this service owns the composition
//! seam, not the policy.
//!
//! House rules: methods are `async fn` with no context parameter —
//! cancellation is future-drop; validation before delegation belongs
//! to `domain` types, never re-stated here.

use central_foundation::failure::Failure;
use central_foundation::identity::OperationId;

use crate::authority::{GenesisPhase, GenesisStatus};
use crate::port::{GenesisPort, HelperClient, HelperRequest, HelperResponse};

/// Orchestrates the genesis lifecycle: init, status, resume, and
/// abandon. It delegates durable persistence to a [`GenesisPort`]
/// implementation and privileged host mutation to a [`HelperClient`]
/// implementation (both wired by the composition root).
///
/// The zero value is not usable — use [`GenesisService::new`].
pub struct GenesisService<G: GenesisPort, H: HelperClient> {
    /// Durable binding/receipt records (upstream `bindingPort`).
    genesis: G,
    /// The privileged helper socket; stored now so the T13 ceremony
    /// wiring composes without changing this type's signature.
    helper: H,
}

impl<G: GenesisPort, H: HelperClient> GenesisService<G, H> {
    /// Returns a service wired to the supplied port implementations.
    pub const fn new(genesis: G, helper: H) -> Self {
        Self { genesis, helper }
    }

    /// Reads the durable genesis state for `host_id`: a committed
    /// receipt for `operation_id` means [`GenesisPhase::Committed`];
    /// a binding without that receipt means
    /// [`GenesisPhase::Prepared`]; no binding means
    /// [`GenesisPhase::Absent`]. The helper is not consulted — this
    /// is a read against durable records, matching upstream's rule
    /// that interrupted genesis resumes only from durable receipts.
    ///
    /// [`GenesisPhase::Abandoned`] is not derivable from the two
    /// records this service reads; the abandon path writes its own
    /// terminal record when the ceremony lands (T13+).
    pub async fn status(
        &self,
        host_id: &str,
        operation_id: OperationId,
    ) -> Result<GenesisStatus, Failure> {
        let receipt = self.genesis.read_genesis_receipt(operation_id).await?;
        if receipt.is_some() {
            return Ok(GenesisStatus {
                operation_id,
                phase: GenesisPhase::Committed,
                receipt,
            });
        }
        let binding = self.genesis.read_binding(host_id).await?;
        Ok(GenesisStatus {
            operation_id,
            phase: if binding.is_some() {
                GenesisPhase::Prepared
            } else {
                GenesisPhase::Absent
            },
            receipt: None,
        })
    }

    /// Passes a helper request through to the privileged socket —
    /// the single seam every `init*`/`prepare`/`up`/`down` verb flows
    /// through once the ceremonies land. Verb-level policy (peer
    /// identity, release digest, ceremony confirmation) is enforced
    /// inside the helper, not here.
    pub async fn invoke_helper(&self, request: HelperRequest) -> Result<HelperResponse, Failure> {
        self.helper.invoke(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{InstanceBinding, UidGidMap};
    use crate::port::HelperOutcome;
    use central_foundation::identity::{ConfigBindingId, InstanceId};
    use std::sync::Mutex;
    use time::macros::datetime;

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

    struct FakeGenesis {
        binding: Mutex<Option<InstanceBinding>>,
        receipts: Mutex<Vec<crate::authority::GenesisReceipt>>,
    }

    impl GenesisPort for FakeGenesis {
        async fn read_binding(&self, _host_id: &str) -> Result<Option<InstanceBinding>, Failure> {
            Ok(self.binding.lock().unwrap().clone())
        }
        async fn write_binding(&self, binding: &InstanceBinding) -> Result<(), Failure> {
            *self.binding.lock().unwrap() = Some(binding.clone());
            Ok(())
        }
        async fn read_genesis_receipt(
            &self,
            operation_id: OperationId,
        ) -> Result<Option<crate::authority::GenesisReceipt>, Failure> {
            Ok(self
                .receipts
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.operation_id == operation_id)
                .cloned())
        }
        async fn write_genesis_receipt(
            &self,
            receipt: &crate::authority::GenesisReceipt,
        ) -> Result<(), Failure> {
            self.receipts.lock().unwrap().push(receipt.clone());
            Ok(())
        }
    }

    struct FakeHelper {
        last: Mutex<Option<HelperRequest>>,
    }

    impl HelperClient for FakeHelper {
        async fn invoke(&self, request: HelperRequest) -> Result<HelperResponse, Failure> {
            let operation_id = request.operation_id.clone();
            *self.last.lock().unwrap() = Some(request);
            Ok(HelperResponse {
                operation_id,
                outcome: HelperOutcome::Success,
                exit_code: 0,
                reason: None,
                result: None,
            })
        }
    }

    fn binding(host_id: &str) -> InstanceBinding {
        InstanceBinding {
            instance_id: InstanceId::new(),
            host_id: host_id.to_string(),
            release_digest: "sha256:rel".to_string(),
            created_at: datetime!(2026-03-04 05:00:00 UTC),
            config_binding_id: ConfigBindingId::new(),
            uid_gid: UidGidMap {
                runtime_uid: 501,
                runtime_gid: 501,
                agent_uid: 502,
                agent_gid: 502,
                browser_uid: 503,
                browser_gid: 503,
            },
        }
    }

    /// The skeleton composes and `status` reads durable state:
    /// absent → prepared → committed exactly as upstream's records
    /// imply, and the helper seam passes requests through untouched.
    #[test]
    fn genesis_service_status_and_helper_passthrough() {
        let genesis = FakeGenesis {
            binding: Mutex::new(None),
            receipts: Mutex::new(Vec::new()),
        };
        let helper = FakeHelper {
            last: Mutex::new(None),
        };
        let service = GenesisService::new(genesis, helper);
        let op = OperationId::new();

        // Absent: no binding, no receipt.
        let status = block_on(service.status("host-1", op)).unwrap();
        assert_eq!(status.phase, GenesisPhase::Absent);
        assert!(status.receipt.is_none());

        // Prepared: binding exists, no committed receipt.
        block_on(service.genesis.write_binding(&binding("host-1"))).unwrap();
        let status = block_on(service.status("host-1", op)).unwrap();
        assert_eq!(status.phase, GenesisPhase::Prepared);

        // Committed: the receipt exists for this operation.
        block_on(
            service
                .genesis
                .write_genesis_receipt(&crate::authority::GenesisReceipt {
                    operation_id: op,
                    instance_id: InstanceId::new(),
                    config_binding_id: ConfigBindingId::new(),
                    uid_gid: UidGidMap {
                        runtime_uid: 501,
                        runtime_gid: 501,
                        agent_uid: 502,
                        agent_gid: 502,
                        browser_uid: 503,
                        browser_gid: 503,
                    },
                    completed_at: datetime!(2026-03-04 05:00:00 UTC),
                }),
        )
        .unwrap();
        let status = block_on(service.status("host-1", op)).unwrap();
        assert_eq!(status.phase, GenesisPhase::Committed);
        assert!(status.receipt.is_some());

        // Helper pass-through.
        let response = block_on(service.invoke_helper(HelperRequest {
            operation_id: "op-init".to_string(),
            verb: crate::authority::HelperVerb::Init,
            payload: None,
        }))
        .unwrap();
        assert_eq!(response.outcome, HelperOutcome::Success);
        assert_eq!(response.operation_id, "op-init");
    }
}
