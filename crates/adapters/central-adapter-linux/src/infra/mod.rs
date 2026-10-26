//! `infra` — the R5 B01 Linux adapter for the advisory consumer
//! (upstream `internal/adapter/advisory`): the hardened on-disk
//! source (`openat2` + root-owned/0400·0600 discipline), the host-fact
//! collector, the anti-rollback time-witness store, the atomic install
//! path, the broker-backed transition recorder, and the deny-safe file
//! store. The domain side of the evaluation lives in
//! `central_infra::advisory`; everything here is boundary I/O only.

pub mod advisory_fetch;
