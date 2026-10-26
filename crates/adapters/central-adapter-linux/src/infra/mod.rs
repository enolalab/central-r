//! `infra` — the R5 B01 Linux adapter for the advisory consumer
//! (upstream `internal/adapter/advisory`): the hardened on-disk
//! source (`openat2` + root-owned/0400·0600 discipline), the host-fact
//! collector, the anti-rollback time-witness store, the atomic install
//! path, the broker-backed transition recorder, and the deny-safe file
//! store. The domain side of the evaluation lives in
//! `central_infra::advisory`; everything here is boundary I/O only.
//!
//! `prepare` is the R5 B02 adapter side (upstream
//! `internal/adapter/dependencyprepare`): the verified lock, the
//! lock-capability-gated fetch + hardened archive staging, the Go
//! module-cache acquirer, the statfs capacity gate, the OCI inventory
//! comparator, the hermetic BuildKit driver, and the release-tree
//! staging/readers. Its domain counterpart is `central_infra::prepare`.

pub mod advisory_fetch;
pub mod prepare;
