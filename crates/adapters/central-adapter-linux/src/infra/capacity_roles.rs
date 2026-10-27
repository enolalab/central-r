//! `capacity_roles` — the durable-payload role-root derivation
//! (upstream `internal/adapter/infralifecycle/capacity_roles_linux.go`).
//! Role roots resolve through [`super::compose::durable_data_bind_mounts`]
//! — the single source of truth shared with the Compose mount renderer,
//! so the two can never disagree about where an instance's data lives.

use central_foundation::failure::Failure;

use super::compose::durable_data_bind_mounts;

/// `CapacityRole` — one of the four fixed durable-payload roles the
/// restore capacity reserve measures free space against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityRole {
    /// `postgres_data`.
    PostgresData,
    /// `postgres_wal`.
    PostgresWal,
    /// `postgres_temp`.
    PostgresTemp,
    /// `object_data`.
    ObjectData,
}

impl CapacityRole {
    /// The upstream role name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PostgresData => "postgres_data",
            Self::PostgresWal => "postgres_wal",
            Self::PostgresTemp => "postgres_temp",
            Self::ObjectData => "object_data",
        }
    }
}

/// `backup.RoleRoots` — the resolved host directory backing each role.
/// The domain type is used directly, as upstream does: `infralifecycle`
/// resolves it and the broker daemon's composition carries the exact
/// same value with no adapter-owned copy to drift.
pub use central_backup::backup::capacity::RoleRoots;

/// `roleServiceCandidates` — durable-data service keys that could back
/// each role, most specific first. Today `postgres_wal`/`postgres_temp`
/// collapse onto the shared `postgres` mount because
/// [`durable_data_bind_mounts`] defines no `postgres-wal`/`postgres-temp`
/// case; the collapse is derived, not asserted.
fn role_service_candidates(role: CapacityRole) -> &'static [&'static str] {
    match role {
        CapacityRole::PostgresData => &["postgres"],
        CapacityRole::PostgresWal => &["postgres-wal", "postgres"],
        CapacityRole::PostgresTemp => &["postgres-temp", "postgres"],
        CapacityRole::ObjectData => &["minio"],
    }
}

/// `RoleRoots` — resolves the host directory backing each role for
/// `instance_id`. Performs no filesystem access (see
/// [`validate_role_root`]'s point-of-use contract).
pub fn role_roots(instance_id: &str) -> Result<RoleRoots, Failure> {
    Ok(RoleRoots {
        postgres_data: role_root(instance_id, CapacityRole::PostgresData)?,
        postgres_wal: role_root(instance_id, CapacityRole::PostgresWal)?,
        postgres_temp: role_root(instance_id, CapacityRole::PostgresTemp)?,
        object_data: role_root(instance_id, CapacityRole::ObjectData)?,
    })
}

/// `roleRoot` — resolves one role to the host root of the first service
/// in its candidate list that actually defines a durable bind mount.
fn role_root(instance_id: &str, role: CapacityRole) -> Result<String, Failure> {
    for service in role_service_candidates(role) {
        let mounts = durable_data_bind_mounts(instance_id, service);
        match mounts.len() {
            0 => continue,
            1 => return Ok(mounts[0].0.clone()),
            n => {
                return Err(Failure::invalid(
                    "INFRALIFECYCLE_CAPACITY_ROLE",
                    format!(
                        "infralifecycle: service {service:?} defines {n} durable mounts, capacity role {} cannot be resolved unambiguously",
                        role.as_str()
                    ),
                ));
            }
        }
    }
    Err(Failure::invalid(
        "INFRALIFECYCLE_CAPACITY_ROLE",
        format!(
            "infralifecycle: no durable bind mount covers capacity role {} for instance",
            role.as_str()
        ),
    ))
}

/// `ValidateRoleRoot` — verifies `path` exists and is a directory.
/// Point-of-use contract: call only immediately before consuming the
/// path (the authorized capacity gate), never at composition resolution.
pub fn validate_role_root(path: &str) -> Result<(), Failure> {
    match std::fs::metadata(path) {
        Err(e) => Err(Failure::invalid(
            "INFRALIFECYCLE_CAPACITY_ROLE",
            format!("infralifecycle: capacity role root {path:?}: {e}"),
        )),
        Ok(info) if !info.is_dir() => Err(Failure::invalid(
            "INFRALIFECYCLE_CAPACITY_ROLE",
            format!("infralifecycle: capacity role root {path:?} is not a directory"),
        )),
        Ok(_) => Ok(()),
    }
}

/// `ValidateRoleRoots` — verifies all four roots, stopping at the
/// first failure.
pub fn validate_role_roots(roots: &RoleRoots) -> Result<(), Failure> {
    for path in [
        &roots.postgres_data,
        &roots.postgres_wal,
        &roots.postgres_temp,
        &roots.object_data,
    ] {
        validate_role_root(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn instance() -> &'static str {
        "test-instance-001"
    }

    /// `TestRoleRootsMatchesRenderedComposeMounts` — the drift guard:
    /// RoleRoots and the Compose renderer must agree on where the
    /// durable data physically lives on the host.
    #[test]
    fn role_roots_matches_rendered_compose_mounts() {
        let postgres_host =
            super::super::compose::durable_service_data_root(instance(), "postgres");
        let minio_host = super::super::compose::durable_service_data_root(instance(), "minio");
        let roots = role_roots(instance()).unwrap();
        assert_eq!(roots.postgres_data, postgres_host);
        assert_eq!(roots.object_data, minio_host);
    }

    #[test]
    fn role_roots_is_deterministic() {
        assert_eq!(
            role_roots(instance()).unwrap(),
            role_roots(instance()).unwrap()
        );
    }

    /// `TestRoleRootsDerivesWALAndTempCollapseFromMountCount` — under the
    /// current single-mount topology, wal/temp collapse onto postgres_data.
    #[test]
    fn role_roots_derives_wal_and_temp_collapse() {
        let roots = role_roots(instance()).unwrap();
        assert_eq!(roots.postgres_wal, roots.postgres_data);
        assert_eq!(roots.postgres_temp, roots.postgres_data);
    }

    #[test]
    fn validate_role_root_rejects_missing_directory() {
        let missing = "/tmp/central-test-does-not-exist-9f3a";
        assert!(validate_role_root(missing).is_err());
    }

    #[test]
    fn validate_role_root_accepts_directory() {
        assert!(validate_role_root("/tmp").is_ok());
    }

    #[test]
    fn validate_role_roots_rejects_first_failure() {
        let roots = RoleRoots {
            postgres_data: "/tmp".to_owned(),
            postgres_wal: "/tmp".to_owned(),
            postgres_temp: "/definitely/missing".to_owned(),
            object_data: "/tmp".to_owned(),
        };
        assert!(validate_role_roots(&roots).is_err());
    }

    #[test]
    fn validate_role_root_rejects_non_directory() {
        let file = std::env::temp_dir().join("central-role-root-file-probe");
        std::fs::write(&file, b"x").unwrap();
        assert!(validate_role_root(file.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(file);
        assert!(Path::new("/tmp").is_dir());
    }
}
