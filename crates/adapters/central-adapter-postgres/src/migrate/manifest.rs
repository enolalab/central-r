//! Compile-time-embedded migration corpus.
//!
//! Every migration SQL file, the runtime-grant reapply script, and
//! `manifest.json` are embedded with `include_str!` from
//! `../../../migrations/` relative to `CARGO_MANIFEST_DIR` — the crate is
//! self-contained exactly like upstream's embedded consts. Migration files
//! are trusted static input executed verbatim via [`sqlx::raw_sql`]; their
//! internal `begin`/`commit`/`SET LOCAL` structure is the durable
//! dirty-intent protocol and must not be split or reordered.
//!
//! `ledger_checksum` strings equal `manifest.json`'s
//! `migrations[].ledger_checksum` verbatim; `sha256` is the file's
//! SHA-256 (asserted against the embedded bytes by unit tests).

#[cfg(test)]
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[cfg(test)]
const MANIFEST_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../migrations/manifest.json"
));

/// One embedded migration: version, ledger checksum, file name, SQL text,
/// and the manifest-pinned SHA-256 of that text.
#[derive(Debug, Clone, Copy)]
pub struct MigrationEntry {
    /// `schema_migrations.version`.
    pub version: i64,
    /// `schema_migrations.checksum` — the `manifest.ledger_checksum` string verbatim.
    pub checksum: &'static str,
    /// Corpus file name (e.g. `"0008_b08_execution_evidence.sql"`).
    pub file_name: &'static str,
    /// Manifest-pinned SHA-256 hex of [`Self::sql`].
    pub sha256: &'static str,
    /// The complete SQL text, executed verbatim via `sqlx::raw_sql`.
    pub sql: &'static str,
}

macro_rules! embed_migration {
    ($version:expr, $checksum:expr, $file:expr, $sha:expr) => {
        MigrationEntry {
            version: $version,
            checksum: $checksum,
            file_name: $file,
            sha256: $sha,
            sql: include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../migrations/",
                $file
            )),
        }
    };
}

/// The 30-file migration chain, manifest order (v0, v8–v14, v16–v37).
/// Version 15 (`b10-artifact-lifecycle-forward-correction`) is a legacy
/// upstream-only migration with no corpus file; [`WITH_V15_CHAIN`] accounts
/// for targets that carry its ledger record.
pub static MIGRATIONS: &[MigrationEntry] = &[
    embed_migration!(
        0,
        "baseline-zero",
        "0000_baseline_zero.sql",
        "cc36f2175b2dca2cd232583ff27ce362a22af51bcf9133b09070fc1e7c095c95"
    ),
    embed_migration!(
        8,
        "b08-execution-evidence",
        "0008_b08_execution_evidence.sql",
        "ea0ea143cd8efb54a9a6d227acd84b09145a134410d98c98e189d092ee1c7029"
    ),
    embed_migration!(
        9,
        "b08-recovery-evidence-correction",
        "0009_b08_recovery_evidence_correction.sql",
        "303062eb5ed586ac5c40bd362e59dc06056bd7f4f4886c066cb93f2617357aea"
    ),
    embed_migration!(
        10,
        "b08-final-safety-correction",
        "0010_b08_final_safety_correction.sql",
        "d20f1bf6feab057f214e400773940767094db40ec13e11d3282a9c8a3b7ac4e6"
    ),
    embed_migration!(
        11,
        "b09-provider-evidence",
        "0011_b09_provider_evidence.sql",
        "01009a1c0698b9d2186c815b956897552ed4c02547f4fa3c9cbde0bf00000765"
    ),
    embed_migration!(
        12,
        "b09-provider-evidence-correction",
        "0012_b09_provider_evidence_correction.sql",
        "6d270ea82818dcb31574706e092113462f1264806faa9fc0da1241e4376cb8ba"
    ),
    embed_migration!(
        13,
        "b09-provider-evidence-response-id-correction",
        "0013_b09_provider_evidence_response_id_correction.sql",
        "9679b93fa937cde62493adfa293715a1558afe8f8151a9deab7b7633aef1b355"
    ),
    embed_migration!(
        14,
        "b10-artifact-lifecycle",
        "0014_b10_artifact_lifecycle.sql",
        "95f0aab6dffae1b68a44afe989a884fc44cb000ec00853b4b168496ff39f3a67"
    ),
    embed_migration!(
        16,
        "b09-provider-tool-call-mapping-correction",
        "0016_b09_provider_tool_call_mapping_correction.sql",
        "91f8bdbca93a2b388488bc65904b9583d4cf01126ff4c5c2e7410ccb4f7e0159"
    ),
    embed_migration!(
        17,
        "b09-durable-context-authority",
        "0017_b09_durable_context_authority.sql",
        "8152823d7d6c630e154b08dbbfe2aa291a112fddd199ee20b61b080e029213c3"
    ),
    embed_migration!(
        18,
        "b09-provider-turn",
        "0018_b09_provider_turn.sql",
        "e30e2bc885f9e1cf3d980f7770c7b8bc3f1ffdfe63505f2fab58c2c7ec23d4d7"
    ),
    embed_migration!(
        19,
        "b11-task-lineage",
        "0019_b11_task_lineage.sql",
        "d361694c8dc814c8266dc7b5c2ac3e746039dbf6f53428479dc89ce71b497dfd"
    ),
    embed_migration!(
        20,
        "b20-sentinel-workspace-id",
        "0020_b20_sentinel_workspace_id.sql",
        "5017c2c7afd7288a5b9c679f2b272f66efbee8c971554e5cf807500bfb0c9dc5"
    ),
    embed_migration!(
        21,
        "b21-task-input-spec-shape",
        "0021_b21_task_input_spec_shape.sql",
        "f87d51826e0ee58b04069a2c39ea68df78711e271dcbcabdb6d2c76d0abb52c4"
    ),
    embed_migration!(
        22,
        "b22-evidence-continuation-parent-grant",
        "0022_b22_evidence_continuation_parent_grant.sql",
        "69da84e4c62ba32c50c84acdd8c5888df3be7e5b6c73c2c6792db5cecf2656fa"
    ),
    embed_migration!(
        23,
        "b23-turn-dispatch-reference",
        "0023_b23_turn_dispatch_reference.sql",
        "e0938ba2d951abbe5f17608864bbbb586e262cd5fa6f00b4e3f6a8dbf4375b2f"
    ),
    embed_migration!(
        24,
        "b24-b09-recovery-reconciliation",
        "0024_b24_b09_recovery_reconciliation.sql",
        "72551358f61a44f6644ddf3e5625e8031988b7ed7d0f78d0dd77d6d6bca59e15"
    ),
    embed_migration!(
        25,
        "b25-recovery-audit",
        "0025_b25_recovery_audit.sql",
        "b10bf9b06727461b6df685acd59248c82f80026b0ff08e422cf214d42f6a37aa"
    ),
    embed_migration!(
        26,
        "b26-recovery-bootstrap-registration",
        "0026_b26_recovery_bootstrap_registration.sql",
        "f85cf627e26ec5b70fd712e41900b7ab1f30a1dc3dc85eaf7953fcb5ba748272"
    ),
    embed_migration!(
        27,
        "b27-recovery-abandonment",
        "0027_b27_recovery_abandonment.sql",
        "7a33bdf200f2894e6c8bbf3bdfb839d55c7e549c4d480854557685b5b8653018"
    ),
    embed_migration!(
        28,
        "b28-quarantine-observation-source",
        "0028_b28_quarantine_observation_source.sql",
        "45afc30c6a5c78b30f0a13a558fcfd29ca55619f12301c441161f3d9087aceeb"
    ),
    embed_migration!(
        29,
        "b29-prune-log",
        "0029_b29_prune_log.sql",
        "1fcb633000859213882ba74e105b8da3216b71e726777532f7bbc45e5aa1feac"
    ),
    embed_migration!(
        30,
        "b30-harness-attempts",
        "0030_b30_harness_attempts.sql",
        "f42a284d96b448ea7e9e1ba44d0c2c975d401be76d335127ea8f93d7b42212a8"
    ),
    embed_migration!(
        31,
        "b31-harness-permission-approvals",
        "0031_b31_harness_permission_approvals.sql",
        "ed2e3ffec4f5fa4e951da87c869df7197e7c54f1f163186a7ffd5794fc26e0e9"
    ),
    embed_migration!(
        32,
        "b32-task-attempt-budgets",
        "0032_b32_task_attempt_budgets.sql",
        "a035df962f4ec23782b7b8b2f19b9d435d47984f9856bf6a0c82f0bd722e5324"
    ),
    embed_migration!(
        33,
        "b33-workflow-graph",
        "0033_b33_workflow_graph.sql",
        "275e4f4d4a003587b54d8ebb419b7c520d6174df36e143751d168a5c7ee83aea"
    ),
    embed_migration!(
        34,
        "b34-artifact-lineage",
        "0034_b34_artifact_lineage.sql",
        "541c1c16637cdb03b407d0e6e291a8a8060330a4cb444efe12e0b6b5e658aa04"
    ),
    embed_migration!(
        35,
        "b35-scheduler-workers",
        "0035_b35_scheduler_workers.sql",
        "73350dbea6e5cd812cbc716eb688e2df64316c7606821271f42ca66d9270cb1e"
    ),
    embed_migration!(
        36,
        "b36-checkpoints",
        "0036_b36_checkpoints.sql",
        "79aa2f9d9191ed1cee95ed4ceaf66ed622b4aa372ace1680f402c2cfe5ea4f0b"
    ),
    embed_migration!(
        37,
        "b37-retry-idempotency",
        "0037_b37_retry_idempotency.sql",
        "c69e9ec03659c063fa1456beac7d6861ba02dd3517168f4daec88ee8ab36edba"
    ),
];

/// The post-`pg_restore` runtime-grant convergence script (trusted static
/// input, replayed verbatim — it carries its own `begin`/`commit`).
pub const REAPPLY_RUNTIME_GRANTS_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../migrations/reapply_incremental_runtime_grants.sql"
));

/// Version 15's upstream-only ledger checksum — admitted history on targets
/// migrated through the legacy `b10-forward-correction` path.
pub const B10_FORWARD_CORRECTION_CHECKSUM: &str = "b10-artifact-lifecycle-forward-correction";

/// The expected `(version, checksum)` ledger record for v15 on the
/// optional legacy chain.
pub const B10_FORWARD_CORRECTION_VERSION: i64 = 15;

/// Latest applied migration version.
pub const LATEST_VERSION: i64 = 37;

/// The chain the corpus itself installs (no v15 record).
pub static WITHOUT_V15_CHAIN: &[(i64, &str)] = &[
    (0, "baseline-zero"),
    (8, "b08-execution-evidence"),
    (9, "b08-recovery-evidence-correction"),
    (10, "b08-final-safety-correction"),
    (11, "b09-provider-evidence"),
    (12, "b09-provider-evidence-correction"),
    (13, "b09-provider-evidence-response-id-correction"),
    (14, "b10-artifact-lifecycle"),
    (16, "b09-provider-tool-call-mapping-correction"),
    (17, "b09-durable-context-authority"),
    (18, "b09-provider-turn"),
    (19, "b11-task-lineage"),
    (20, "b20-sentinel-workspace-id"),
    (21, "b21-task-input-spec-shape"),
    (22, "b22-evidence-continuation-parent-grant"),
    (23, "b23-turn-dispatch-reference"),
    (24, "b24-b09-recovery-reconciliation"),
    (25, "b25-recovery-audit"),
    (26, "b26-recovery-bootstrap-registration"),
    (27, "b27-recovery-abandonment"),
    (28, "b28-quarantine-observation-source"),
    (29, "b29-prune-log"),
    (30, "b30-harness-attempts"),
    (31, "b31-harness-permission-approvals"),
    (32, "b32-task-attempt-budgets"),
    (33, "b33-workflow-graph"),
    (34, "b34-artifact-lineage"),
    (35, "b35-scheduler-workers"),
    (36, "b36-checkpoints"),
    (37, "b37-retry-idempotency"),
];

/// The optional legacy chain: identical to [`WITHOUT_V15_CHAIN`] plus the
/// v15 forward-correction record after v14.
pub static WITH_V15_CHAIN: &[(i64, &str)] = &[
    (0, "baseline-zero"),
    (8, "b08-execution-evidence"),
    (9, "b08-recovery-evidence-correction"),
    (10, "b08-final-safety-correction"),
    (11, "b09-provider-evidence"),
    (12, "b09-provider-evidence-correction"),
    (13, "b09-provider-evidence-response-id-correction"),
    (14, "b10-artifact-lifecycle"),
    (15, "b10-artifact-lifecycle-forward-correction"),
    (16, "b09-provider-tool-call-mapping-correction"),
    (17, "b09-durable-context-authority"),
    (18, "b09-provider-turn"),
    (19, "b11-task-lineage"),
    (20, "b20-sentinel-workspace-id"),
    (21, "b21-task-input-spec-shape"),
    (22, "b22-evidence-continuation-parent-grant"),
    (23, "b23-turn-dispatch-reference"),
    (24, "b24-b09-recovery-reconciliation"),
    (25, "b25-recovery-audit"),
    (26, "b26-recovery-bootstrap-registration"),
    (27, "b27-recovery-abandonment"),
    (28, "b28-quarantine-observation-source"),
    (29, "b29-prune-log"),
    (30, "b30-harness-attempts"),
    (31, "b31-harness-permission-approvals"),
    (32, "b32-task-attempt-budgets"),
    (33, "b33-workflow-graph"),
    (34, "b34-artifact-lineage"),
    (35, "b35-scheduler-workers"),
    (36, "b36-checkpoints"),
    (37, "b37-retry-idempotency"),
];

#[cfg(test)]
#[derive(Debug, Deserialize)]
struct ManifestFile {
    migrations: Vec<ManifestMigration>,
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
struct ManifestMigration {
    version: i64,
    ledger_checksum: String,
    file: String,
    sha256: String,
}

/// SHA-256 hex digest of `bytes` (used by tests to pin the embedded corpus
/// against `manifest.json`).
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use core::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Cross-check the hardcoded table against the embedded `manifest.json`.
/// Called by tests; the two must never drift.
///
/// # Errors
/// Returns a description of the first drift found.
#[cfg(test)]
pub(crate) fn verify_embedded_manifest() -> Result<(), String> {
    let parsed: ManifestFile =
        serde_json::from_str(MANIFEST_JSON).map_err(|e| format!("manifest.json parse: {e}"))?;
    if parsed.migrations.len() != MIGRATIONS.len() {
        return Err(format!(
            "manifest has {} migrations, table has {}",
            parsed.migrations.len(),
            MIGRATIONS.len()
        ));
    }
    for (entry, m) in MIGRATIONS.iter().zip(&parsed.migrations) {
        if entry.version != m.version {
            return Err(format!("version drift: {} vs {}", entry.version, m.version));
        }
        if entry.checksum != m.ledger_checksum {
            return Err(format!(
                "checksum drift v{}: {} vs {}",
                m.version, entry.checksum, m.ledger_checksum
            ));
        }
        if entry.file_name != m.file {
            return Err(format!("file drift v{}: {}", m.version, m.file));
        }
        if entry.sha256 != m.sha256 {
            return Err(format!("sha256 table drift v{}", m.version));
        }
        let actual = sha256_hex(entry.sql.as_bytes());
        if actual != m.sha256 {
            return Err(format!(
                "embedded SQL hash mismatch v{}: {actual} vs {}",
                m.version, m.sha256
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_table_matches_embedded_json_and_hashes() {
        assert!(
            verify_embedded_manifest().is_ok(),
            "{:?}",
            verify_embedded_manifest().err()
        );
    }

    #[test]
    fn latest_version_is_37_with_30_migrations() {
        assert_eq!(LATEST_VERSION, 37);
        assert_eq!(MIGRATIONS.len(), 30);
        assert_eq!(
            MIGRATIONS.last().map(|m| (m.version, m.checksum)),
            Some((37, "b37-retry-idempotency"))
        );
        assert_eq!(WITHOUT_V15_CHAIN.len(), 30);
        assert_eq!(WITH_V15_CHAIN.len(), 31);
        for (entry, chain) in MIGRATIONS.iter().zip(WITHOUT_V15_CHAIN) {
            assert_eq!(entry.version, chain.0);
            assert_eq!(entry.checksum, chain.1);
        }
    }
}
