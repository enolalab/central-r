//! `internal/adapter/dependencyprepare/versionzero_linux.go` —
//! `EnsureVersionZeroReceipt`: populate the instance's active
//! dependency receipt exactly once at provisioning, from the vendored
//! dependency lock (ADR 0020). First-write-only and non-interactive:
//! an `active` selector that already resolves is returned untouched;
//! one that exists but does not resolve is a corrupt state this
//! refuses to repair; population goes through the staged-candidate
//! path (`Stage` → `SwitchSelector`), never a hand-written `active`
//! file.

use std::path::Path;

use central_foundation::failure::Failure;
use central_infra::domain::{
    Candidate, DependencyReceipt, PreparedDependencySet, PreparedMode, ServiceMode,
    new_admission_binding, selector_token,
};

use super::{OpDeadline, lock::LockAdapter, store::CandidateStore};

/// `VersionZeroSelector`.
pub const VERSION_ZERO_SELECTOR: &str = "version-zero";

/// `EnsureVersionZeroReceipt` — `(receipt, populated)`.
pub fn ensure_version_zero_receipt(
    deadline: OpDeadline,
    dependency_root: &Path,
) -> Result<(DependencyReceipt, bool), Failure> {
    if dependency_root.as_os_str().is_empty() {
        return Err(Failure::invalid(
            "dependencyprepare_version_zero",
            "dependencyprepare: version zero: dependency root is required",
        ));
    }
    let wrap = |e: Failure| {
        Failure::new(
            e.kind(),
            e.code(),
            format!("dependencyprepare: version zero: {}", e.message()),
        )
    };
    let store = CandidateStore::new(None, dependency_root);

    let active_path = dependency_root.join("active");
    match std::fs::symlink_metadata(&active_path) {
        Ok(_) => {
            let receipt = store.active(deadline).map_err(|e| {
                wrap(Failure::invalid(
                    e.code(),
                    format!(
                        "active selector exists but does not resolve; refusing to replace it: {}",
                        e.message()
                    ),
                ))
            })?;
            receipt.validate_b03().map_err(|e| {
                wrap(Failure::invalid(
                    e.code(),
                    format!(
                        "existing active receipt is incomplete; refusing to replace it: {}",
                        e.message()
                    ),
                ))
            })?;
            return Ok((receipt, false));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(wrap(Failure::internal(
                "dependencyprepare_version_zero",
                format!("inspect active selector: {e}"),
            )));
        }
    }

    let lock = central_infra::prepare::load_lock().map_err(wrap)?;
    lock.verify_identities().map_err(wrap)?;
    let lock_hash = lock.canonical_hash().map_err(wrap)?;

    // Restage through a lock-bound store so the version-zero manifest
    // records the dependency-lock digest it was populated from.
    let store = CandidateStore::new(Some(LockAdapter::with_lock(lock.clone())), dependency_root);

    // Version zero inherits every mode's inventory from the lock,
    // including `minio`'s placeholder — inherited, not introduced
    // here (upstream's comment verbatim in effect).
    let mut set = PreparedDependencySet {
        modes: Vec::with_capacity(lock.modes.len()),
    };
    for mode in &lock.modes {
        set.modes.push(PreparedMode {
            mode: mode.mode,
            inventory: mode.inventory.clone(),
        });
    }
    set.validate_b03().map_err(wrap)?;
    // The seventh Compose service (C02's throughput probe) is not
    // part of `validate_b03`'s contract, but compose rendering needs
    // its inventory, so a lock without it fails here.
    set.lookup(ServiceMode::PostgresThroughputProvision)
        .map_err(wrap)?;

    // The population is its own operation, and it names itself.
    let operation_id = format!("version-zero:{lock_hash}");
    let staged = store
        .stage(
            deadline,
            &Candidate {
                operation_id: operation_id.clone(),
                selector: VERSION_ZERO_SELECTOR.to_owned(),
                phase: Some(central_infra::domain::PreparePhase::Pending),
                dependency_set: set,
                ..Candidate::default()
            },
        )
        .map_err(wrap)?;
    let binding =
        new_admission_binding(&operation_id, &selector_token(&staged.selector)).map_err(wrap)?;
    let receipt = store
        .switch_selector(deadline, &staged, &binding)
        .map_err(wrap)?;
    receipt.validate_b03().map_err(|e| {
        wrap(Failure::invalid(
            e.code(),
            format!("populated receipt is incomplete: {}", e.message()),
        ))
    })?;
    Ok((receipt, true))
}
