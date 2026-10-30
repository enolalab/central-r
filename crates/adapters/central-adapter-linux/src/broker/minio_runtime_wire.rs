//! The wire-facing `MinioRuntimeUseRequest` — the domain type carries no
//! serde; this mirrors the JSON shape `secretbootstrap.MinioRuntimeUseRequest`
//! has on the socket and converts to the domain type for `validate(now)`.

use central_foundation::failure::Failure;
use central_infra::domain::{MinioRuntimeUseRequest, Purpose, ServiceMode};
use serde::Deserialize;
use time::OffsetDateTime;

/// `secretbootstrap.MinioRuntimeUseRequest` on the wire.
#[derive(Debug, Deserialize)]
pub(crate) struct WireMinioRuntimeUseRequest {
    pub instance_id: String,
    pub operation_id: String,
    pub receipt_id: String,
    pub opaque_generation: String,
    pub bucket: String,
    pub key_prefix: String,
    pub service: String,
    pub target: String,
    pub uid: u32,
    pub gid: u32,
    pub purpose: String,
    pub fencing_token: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub deadline: OffsetDateTime,
}

impl WireMinioRuntimeUseRequest {
    /// Map to the domain type; `Purpose::MinioRuntime` is enforced here
    /// (`validate` re-checks it anyway).
    pub(crate) fn to_domain(&self) -> Result<MinioRuntimeUseRequest, Failure> {
        if self.purpose != Purpose::MinioRuntime.as_str() {
            return Err(Failure::invalid(
                "secretbootstrap",
                "secretbootstrap: invalid minio runtime binding",
            ));
        }
        Ok(MinioRuntimeUseRequest {
            instance_id: self.instance_id.clone(),
            operation_id: self.operation_id.clone(),
            receipt_id: self.receipt_id.clone(),
            opaque_generation: self.opaque_generation.clone(),
            bucket: self.bucket.clone(),
            key_prefix: self.key_prefix.clone(),
            service: self.service.clone(),
            target: self.target.clone(),
            uid: self.uid,
            gid: self.gid,
            purpose: Purpose::MinioRuntime,
            fencing_token: self.fencing_token,
            deadline: self.deadline,
        })
    }
}

/// Domain's `ServiceMode::MinioProvision` wire name — the provisioner
/// identity (`minio-provision`).
#[allow(dead_code)]
pub(crate) const MINIO_PROVISION_SERVICE: &str = ServiceMode::MinioProvision.as_str();
