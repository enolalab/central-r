//! `b10_runtime_binding.go` — the durable authority for `minio_runtime_v1`
//! credential handoffs, ported verbatim.
//!
//! The protected-generation store alone cannot answer the two questions the
//! B10 broker handler must answer before handing a peer a sealed credential:
//! which instance the generation belongs to, and whether its single handoff
//! was already taken. This file-backed store answers both; the one-shot is an
//! `O_EXCL` create the kernel makes atomic across processes.

use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::durable;
use super::wire::hex_encode;

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker", msg.into())
}

const BINDING_DIR: &str = "minio-runtime-bindings";
const CONSUMPTION_DIR: &str = "minio-runtime-consumptions";
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

pub(crate) const DELIVERY_PENDING: &str = "delivery_pending";
pub(crate) const DELIVERY_DELIVERED: &str = "delivered";
pub(crate) const DELIVERY_RECONCILIATION: &str = "reconciliation";

pub(crate) const ERR_BINDING_UNAVAILABLE: &str = "broker: minio runtime binding unavailable";
pub(crate) const ERR_FENCE_STALE: &str = "broker: minio runtime fencing token is stale";
pub(crate) const ERR_CONSUMED: &str = "broker: minio runtime generation already consumed";

fn store_err(msg: impl core::fmt::Display) -> Failure {
    internal(format!("minio runtime binding store: {msg}"))
}

/// `minioRuntimeBinding` — the immutable authority record for one
/// `minio_runtime_v1` protected generation. Carries no credential material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinioRuntimeBinding {
    pub generation_id: String,
    pub instance_id: String,
    pub bucket: String,
    pub key_prefix: String,
    pub fence_generation: u64,
    pub created_at: String,
}

/// `minioRuntimeConsumption` — the durable record that a generation's single
/// handoff was taken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinioRuntimeConsumption {
    pub consumption_id: String,
    pub generation_id: String,
    pub instance_id: String,
    pub operation_id: String,
    pub receipt_id: String,
    pub fence_generation: u64,
    pub consumed_at: String,
    pub delivery_state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub failure_code: String,
}

/// `minioRuntimeConsumeRequest` — the caller-presented scope; every field is
/// compared against the durable binding, none is authoritative.
#[derive(Debug, Clone)]
pub struct MinioRuntimeConsumeRequest {
    pub generation_id: String,
    pub instance_id: String,
    pub bucket: String,
    pub key_prefix: String,
    pub operation_id: String,
    pub receipt_id: String,
    pub fencing_token: u64,
}

pub struct MinioRuntimeBindingStore {
    binding_root: PathBuf,
    consumption_root: PathBuf,
}

fn generation_key(generation_id: &str) -> String {
    let sum = Sha256::digest(generation_id.as_bytes());
    hex_encode(&sum)
}

fn rfc3339_now() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl MinioRuntimeBindingStore {
    /// `newMinioRuntimeBindingStore(brokerRoot)`.
    pub(crate) fn new(broker_root: &Path) -> Result<Self, Failure> {
        let binding_root = broker_root.join(BINDING_DIR);
        let consumption_root = broker_root.join(CONSUMPTION_DIR);
        durable::mkdir_p(&binding_root, PRIVATE_DIR_MODE)
            .map_err(|e| store_err(format!("create binding root: {e}")))?;
        durable::mkdir_p(&consumption_root, PRIVATE_DIR_MODE)
            .map_err(|e| store_err(format!("create consumption root: {e}")))?;
        Ok(Self {
            binding_root,
            consumption_root,
        })
    }

    fn binding_path(&self, generation_id: &str) -> PathBuf {
        self.binding_root
            .join(format!("{}.json", generation_key(generation_id)))
    }

    fn consumption_path(&self, generation_id: &str) -> PathBuf {
        self.consumption_root
            .join(format!("{}.json", generation_key(generation_id)))
    }

    /// `Bind` — install the immutable authority record for a freshly created
    /// generation; create-only, the scope never changes afterwards.
    pub(crate) fn bind(&self, mut binding: MinioRuntimeBinding) -> Result<(), Failure> {
        if binding.generation_id.trim().is_empty()
            || binding.instance_id.trim().is_empty()
            || binding.bucket.trim().is_empty()
            || binding.key_prefix.trim().is_empty()
            || binding.fence_generation == 0
        {
            return Err(store_err("incomplete binding"));
        }
        binding.created_at = rfc3339_now();
        let data =
            serde_json::to_vec(&binding).map_err(|e| store_err(format!("marshal binding: {e}")))?;
        self.write_exclusive(&self.binding_path(&binding.generation_id), &data)?;
        durable::sync_dir(&self.binding_root)
            .map_err(|e| store_err(format!("sync binding root: {e}")))?;
        Ok(())
    }

    /// `Consume` — validate the declared scope against the binding, then take
    /// the generation's single handoff via the atomic `O_EXCL` create.
    pub(crate) fn consume(
        &self,
        req: MinioRuntimeConsumeRequest,
    ) -> Result<MinioRuntimeConsumption, Failure> {
        if req.generation_id.trim().is_empty()
            || req.instance_id.trim().is_empty()
            || req.bucket.trim().is_empty()
            || req.key_prefix.trim().is_empty()
            || req.operation_id.trim().is_empty()
            || req.receipt_id.trim().is_empty()
        {
            return Err(Failure::invalid("broker", ERR_BINDING_UNAVAILABLE));
        }
        let binding = self.load_binding(&req.generation_id)?;
        if binding.instance_id != req.instance_id
            || binding.bucket != req.bucket
            || binding.key_prefix != req.key_prefix
        {
            return Err(Failure::denied("broker", ERR_BINDING_UNAVAILABLE));
        }
        if binding.fence_generation != req.fencing_token {
            return Err(Failure::denied("broker", ERR_FENCE_STALE));
        }
        let consumption = MinioRuntimeConsumption {
            consumption_id: uuid::Uuid::new_v4().to_string(),
            generation_id: req.generation_id.clone(),
            instance_id: req.instance_id,
            operation_id: req.operation_id,
            receipt_id: req.receipt_id,
            fence_generation: req.fencing_token,
            consumed_at: rfc3339_now(),
            delivery_state: DELIVERY_PENDING.to_owned(),
            failure_code: String::new(),
        };
        let data = serde_json::to_vec(&consumption)
            .map_err(|e| store_err(format!("marshal consumption: {e}")))?;
        self.write_exclusive(&self.consumption_path(&req.generation_id), &data)?;
        durable::sync_dir(&self.consumption_root)
            .map_err(|e| store_err(format!("sync consumption root: {e}")))?;
        Ok(consumption)
    }

    /// `RecordDelivery` — advance a consumed generation's disposition; only
    /// ever moves out of `delivery_pending`, so a late or duplicate record
    /// cannot rewrite a settled outcome.
    pub(crate) fn record_delivery(
        &self,
        generation_id: &str,
        state: &str,
        failure_code: &str,
    ) -> Result<(), Failure> {
        match state {
            DELIVERY_DELIVERED if !failure_code.is_empty() => {
                return Err(store_err("delivered record carries a failure code"));
            }
            DELIVERY_RECONCILIATION if failure_code.is_empty() => {
                return Err(store_err("reconciliation record needs a closed reason"));
            }
            DELIVERY_DELIVERED | DELIVERY_RECONCILIATION => {}
            _ => return Err(store_err("invalid delivery state")),
        }
        let path = self.consumption_path(generation_id);
        let raw = durable::read_file(&path)
            .map_err(|_| Failure::invalid("broker", ERR_BINDING_UNAVAILABLE))?;
        let mut consumption: MinioRuntimeConsumption = serde_json::from_slice(&raw)
            .map_err(|e| store_err(format!("decode consumption: {e}")))?;
        if consumption.delivery_state != DELIVERY_PENDING {
            return Err(Failure::denied("broker", ERR_CONSUMED));
        }
        consumption.delivery_state = state.to_owned();
        consumption.failure_code = failure_code.to_owned();
        let data = serde_json::to_vec(&consumption)
            .map_err(|e| store_err(format!("marshal delivery: {e}")))?;
        let tmp = path.with_extension("tmp");
        durable::write_file(&tmp, &data, PRIVATE_FILE_MODE)
            .map_err(|e| store_err(format!("write delivery: {e}")))?;
        durable::sync_file(&tmp).map_err(|e| store_err(format!("sync delivery: {e}")))?;
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            store_err(format!("install delivery: {e}"))
        })?;
        durable::sync_dir(&self.consumption_root)
            .map_err(|e| store_err(format!("sync consumption root: {e}")))?;
        Ok(())
    }

    fn load_binding(&self, generation_id: &str) -> Result<MinioRuntimeBinding, Failure> {
        let raw = durable::read_file(&self.binding_path(generation_id))
            .map_err(|_| Failure::invalid("broker", ERR_BINDING_UNAVAILABLE))?;
        let binding: MinioRuntimeBinding =
            serde_json::from_slice(&raw).map_err(|e| store_err(format!("decode binding: {e}")))?;
        if binding.generation_id != generation_id {
            return Err(Failure::invalid("broker", ERR_BINDING_UNAVAILABLE));
        }
        Ok(binding)
    }

    /// `writeExclusive` — `O_EXCL` create; `EEXIST` is the cross-process
    /// decision point mapping to `ERR_CONSUMED`.
    fn write_exclusive(&self, path: &Path, data: &[u8]) -> Result<(), Failure> {
        match durable::open_exclusive(path, PRIVATE_FILE_MODE) {
            Err(rustix::io::Errno::EXIST) => Err(Failure::denied("broker", ERR_CONSUMED)),
            Err(e) => Err(store_err(format!("reserve record: {e}"))),
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(data)
                    .and_then(|()| file.sync_all())
                    .map_err(|e| {
                        drop(file);
                        let _ = std::fs::remove_file(path);
                        store_err(format!("write record: {e}"))
                    })?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::TempDir;

    fn store(dir: &TempDir) -> MinioRuntimeBindingStore {
        MinioRuntimeBindingStore::new(dir).unwrap()
    }

    fn request(gen_id: &str) -> MinioRuntimeConsumeRequest {
        MinioRuntimeConsumeRequest {
            generation_id: gen_id.to_owned(),
            instance_id: "inst-1".to_owned(),
            bucket: "central-artifacts-v1".to_owned(),
            key_prefix: "v1/staging/ v1/ready/".to_owned(),
            operation_id: "op-1".to_owned(),
            receipt_id: "rcpt-1".to_owned(),
            fencing_token: 7,
        }
    }

    #[test]
    fn bind_consume_record_delivery_round_trip() {
        let dir = TempDir::new("b10");
        let s = store(&dir);
        s.bind(MinioRuntimeBinding {
            generation_id: "gen-1".to_owned(),
            instance_id: "inst-1".to_owned(),
            bucket: "central-artifacts-v1".to_owned(),
            key_prefix: "v1/staging/ v1/ready/".to_owned(),
            fence_generation: 7,
            created_at: String::new(),
        })
        .unwrap();
        let c = s.consume(request("gen-1")).unwrap();
        assert_eq!(c.delivery_state, DELIVERY_PENDING);
        s.record_delivery("gen-1", DELIVERY_DELIVERED, "").unwrap();
    }

    #[test]
    fn consume_rejects_replay_and_stale_fence() {
        let dir = TempDir::new("b10");
        let s = store(&dir);
        s.bind(MinioRuntimeBinding {
            generation_id: "gen-1".to_owned(),
            instance_id: "inst-1".to_owned(),
            bucket: "central-artifacts-v1".to_owned(),
            key_prefix: "v1/staging/ v1/ready/".to_owned(),
            fence_generation: 7,
            created_at: String::new(),
        })
        .unwrap();
        s.consume(request("gen-1")).unwrap();
        assert!(s.consume(request("gen-1")).is_err());
        let mut stale = request("gen-2");
        stale.fencing_token = 8;
        s.bind(MinioRuntimeBinding {
            generation_id: "gen-2".to_owned(),
            instance_id: "inst-1".to_owned(),
            bucket: "central-artifacts-v1".to_owned(),
            key_prefix: "v1/staging/ v1/ready/".to_owned(),
            fence_generation: 7,
            created_at: String::new(),
        })
        .unwrap();
        assert!(s.consume(stale).is_err());
    }
}
