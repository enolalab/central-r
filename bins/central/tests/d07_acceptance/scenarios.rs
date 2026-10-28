//! `d07_scenarios_test.go` — the eight Slice-D dossier scenarios,
//! asserting through the real operator surface only. Assertion bodies
//! map one-for-one onto upstream's; fixture seams live in `harness`/
//! `seams`.

use central_adapter_linux::helper::audit::{REASON_AUDIT_REPAIR_REFUSED, load_deny_safe};
use central_adapter_linux::helper::grant::GrantKind;
use central_adapter_linux::infra::advisory_fetch::FileDenySafeStore;
use central_infra::advisory::{self, Code, Outcome, State};
use central_infra::destructive;
use central_infra::portable::{Bx1Token, verify_bx1_token};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::harness::{Envelope, stand_up};
use crate::{ScenarioVerdict, hex_lower, skipped};

const WIPE_EVIDENCE: &str = "slice-d-wipe-reseed.json";
const EXPORT_EVIDENCE: &str = "slice-d-export.json";
const IMPORT_EVIDENCE: &str = "slice-d-import.json";
const AUDIT_EVIDENCE: &str = "slice-d-state-audit.json";
const RESCUE_EVIDENCE: &str = "slice-d-rescue.json";
/// `command.PrunePlanFilePrefix`.
const PRUNE_PLAN_PREFIX: &str = "slice-d-prune-plan-";

const PRODUCTION_TIER_SKIP: &str =
    "production tier: root install not yet rehearsed in this environment";

fn details<'a>(envelope: &'a Envelope, command: &str) -> &'a serde_json::Value {
    assert!(
        envelope.details.is_object(),
        "{command}: details not an object: {}",
        envelope.details
    );
    &envelope.details
}

fn str_field<'a>(envelope: &'a Envelope, field: &str) -> &'a str {
    envelope.details[field]
        .as_str()
        .unwrap_or_else(|| panic!("details.{field} missing in {}", envelope.details))
}

fn bool_field(envelope: &Envelope, field: &str) -> bool {
    envelope.details[field]
        .as_bool()
        .unwrap_or_else(|| panic!("details.{field} missing in {}", envelope.details))
}

/// Counter details are `skip_serializing_if = 0`: an absent
/// `tamper_count` IS the clean zero, exactly what `omitempty` means
/// in upstream's `cli.LocalResult` details.
fn i64_field(envelope: &Envelope, field: &str) -> i64 {
    envelope.details[field].as_i64().unwrap_or(0)
}

// S1: the full D01 loop through the real surface. A sealed backup
// exists, the grant spends, the instance is wiped and reseeded under
// a new identity, and the evidence carries the checkpoint that
// authorized it.
pub(crate) fn wipe_reseed() -> ScenarioVerdict {
    let Some(env) = stand_up() else {
        return skipped(PRODUCTION_TIER_SKIP);
    };
    let backup_id = env.seal_backup();
    env.install_backup_create(&backup_id);
    env.issue(GrantKind::Wipe, "");

    let target = env.instances.join(&env.instance_id);
    let envelope = env.run(&[
        "local",
        "wipe",
        "--target",
        target.to_str().expect("target utf8"),
    ]);
    assert!(
        envelope.exit_code == 0 && envelope.reason == "ok",
        "wipe: exit={} reason={}",
        envelope.exit_code,
        envelope.reason
    );
    let details = details(&envelope, "wipe");
    let wiped = details["wiped_instance_id"].as_str().unwrap_or_default();
    let new_id = details["new_instance_id"].as_str().unwrap_or_default();
    assert!(
        wiped == env.instance_id && !new_id.is_empty() && new_id != env.instance_id,
        "wipe details={details}"
    );
    assert!(
        details["checkpoint_backup_id"].as_str() == Some(backup_id.as_str()),
        "checkpoint={}, want {backup_id}",
        details["checkpoint_backup_id"]
    );
    assert!(
        std::fs::symlink_metadata(&target).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "wiped instance root survives"
    );
    assert!(
        env.instances.join(new_id).is_dir(),
        "reseeded instance missing"
    );
    let consumed = env.consumed();
    assert!(
        consumed.len() == 1 && consumed[0].grant.kind == GrantKind::Wipe.as_str(),
        "consumed={consumed:?}"
    );
    env.read_file(WIPE_EVIDENCE);
    ScenarioVerdict {
        evidence_files: Some(vec![WIPE_EVIDENCE.to_owned()]),
        work_dir: Some(env.work.clone()),
        _tree: Some(env.tree.clone()),
        notes: vec![
            "checkpoint backup created by fixture sealing through the production repository APIs; the wipe verified it sealed for real".to_owned(),
            "grant-mode ceremony spent one unbound wipe grant with a consumption record".to_owned(),
            "d07BackupCreate sits server-side in this port (upstream fakes the in-process client): the socket, matrix, and gate stay real".to_owned(),
        ],
        ..ScenarioVerdict::default()
    }
}

// S2: a Denied advisory blocks the wipe before any ceremony: no grant
// is spent, the tree is untouched, and the refusal names signed
// denial.
pub(crate) fn signed_denial() -> ScenarioVerdict {
    let Some(env) = stand_up() else {
        return skipped(PRODUCTION_TIER_SKIP);
    };
    let backup_id = env.seal_backup();
    env.install_backup_create(&backup_id);
    env.evaluator.set(State::Denied);

    let target = env.instances.join(&env.instance_id);
    let envelope = env.run(&[
        "local",
        "wipe",
        "--target",
        target.to_str().expect("target utf8"),
    ]);
    assert!(
        envelope.reason == destructive::REASON_WIPE_DENIED_SIGNED,
        "reason={}",
        envelope.reason
    );
    assert!(env.consumed().is_empty(), "denied wipe spent a grant");
    assert!(
        target.join("config.json").is_file(),
        "denied wipe touched the tree"
    );
    ScenarioVerdict {
        _tree: Some(env.tree.clone()),
        ..ScenarioVerdict::default()
    }
}

// S3: export a sealed backup, verify the token WITHOUT the helper
// (the independence the dossier demands: parsing and signature
// verification through the portable package directly), wipe for
// freshness, and import onto the fresh instance. The fixture tier
// composes no data-plane engine (no PostgreSQL, no MinIO, no
// provisioner), so staging completes and the suite asserts the honest
// staging-only boundary ADR 0034 defines for that composition; the
// production tier asserts the full chain.
pub(crate) fn export_import() -> ScenarioVerdict {
    let Some(env) = stand_up() else {
        return skipped(PRODUCTION_TIER_SKIP);
    };
    let backup_id = env.seal_backup();

    env.issue(GrantKind::BackupExport, "");
    let out_dir = env.work.join("out");
    std::fs::create_dir_all(&out_dir).expect("create export out dir");
    let exported = env.run(&[
        "backup",
        "export",
        &format!("--backup={backup_id}"),
        &format!("--out={}", out_dir.to_str().expect("out dir utf8")),
    ]);
    assert!(
        exported.exit_code == 0 && exported.reason == "ok",
        "export: exit={} reason={}",
        exported.exit_code,
        exported.reason
    );
    let bundle_path = out_dir.join(str_field(&exported, "bundle_file"));
    let token_path = out_dir.join(str_field(&exported, "token_file"));

    // Independent verification: no helper, no grant, just the token,
    // the bundle bytes, and the pinned trust key.
    let bundle_bytes = std::fs::read(&bundle_path).expect("read bundle");
    let sum = Sha256::digest(&bundle_bytes);
    assert!(
        hex_lower(sum) == str_field(&exported, "bundle_sha256"),
        "bundle bytes do not match the evidenced digest"
    );
    let token_raw = std::fs::read(&token_path).expect("read token");
    let token: Bx1Token = serde_json::from_slice(&token_raw).expect("token does not parse");
    verify_bx1_token(
        &token,
        str_field(&exported, "public_key_hex"),
        str_field(&exported, "bundle_sha256"),
        OffsetDateTime::now_utc(),
    )
    .expect("independent token verify failed");

    // Freshness via D01: the import target is a wiped-and-reseeded
    // instance, not the exporting one.
    env.install_backup_create(&backup_id);
    env.issue(GrantKind::Wipe, "");
    let target = env.instances.join(&env.instance_id);
    let wiped = env.run(&[
        "local",
        "wipe",
        "--target",
        target.to_str().expect("target utf8"),
    ]);
    assert!(wiped.exit_code == 0, "freshness wipe: {}", wiped.reason);
    let new_instance_id = wiped.details["new_instance_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        !new_instance_id.is_empty(),
        "freshness wipe named no new instance"
    );
    env.rebind_import(&new_instance_id);

    env.issue(GrantKind::BackupImport, "");
    let imported = env.run(&[
        "backup",
        "import",
        &format!("--bundle={}", bundle_path.to_str().expect("bundle utf8")),
        &format!("--token={}", token_path.to_str().expect("token utf8")),
        &format!("--trust-key={}", str_field(&exported, "public_key_hex")),
    ]);
    assert!(
        imported.exit_code == 0 && imported.reason == "ok",
        "import: exit={} reason={}",
        imported.exit_code,
        imported.reason
    );
    assert!(
        !bool_field(&imported, "data_plane_restored"),
        "fixture-tier import restored the data plane with no engine composed"
    );
    env.read_file(IMPORT_EVIDENCE);
    env.read_file(EXPORT_EVIDENCE);
    ScenarioVerdict {
        evidence_files: Some(vec![EXPORT_EVIDENCE.to_owned(), IMPORT_EVIDENCE.to_owned()]),
        work_dir: Some(env.work.clone()),
        _tree: Some(env.tree.clone()),
        notes: vec![
            "token verified independently of the helper (parse + ed25519 + digest match)".to_owned(),
            "import staging completed on a D01-freshened instance; data plane honestly unrestored (no engine in fixture)".to_owned(),
        ],
        disclosures: vec![
            "full round-trip (pg_restore/MinIO import write) is production-tier only; see d07 production evidence".to_owned(),
        ],
        ..ScenarioVerdict::default()
    }
}

// S4: delete with the production engine unplumbed refuses closed. The
// refusal carries the documented code, happens before any
// destruction, and leaves the sealed backup intact. The
// retention/reference/delete engine logic itself is covered by the
// destructive unit suite and the v29 migration tests; this scenario
// covers the production wiring's honest refusal.
pub(crate) fn delete_fail_closed() -> ScenarioVerdict {
    let Some(env) = stand_up() else {
        return skipped(PRODUCTION_TIER_SKIP);
    };
    let backup_id = env.seal_backup();

    // No --backup: resolution itself needs the source, so the refusal
    // lands before any ceremony and spends no grant.
    let unresolved = env.run(&["backup", "delete"]);
    assert!(
        unresolved.reason == destructive::REASON_DELETE_UNAVAILABLE,
        "reason={}",
        unresolved.reason
    );
    assert!(env.consumed().is_empty(), "unresolved delete spent a grant");

    // Explicit backup: resolution succeeds, the ceremony spends, then
    // the source check refuses. Nothing is deleted either way.
    env.issue(GrantKind::BackupDelete, "");
    let explicit = env.run(&["backup", "delete", &format!("--backup={backup_id}")]);
    assert!(
        explicit.reason == destructive::REASON_DELETE_UNAVAILABLE,
        "reason={}",
        explicit.reason
    );
    let repository = env.open_repo_ro();
    repository
        .sealed_backup_ids()
        .expect("repo unreadable after refused delete");
    repository.close().expect("close repository");
    ScenarioVerdict {
        _tree: Some(env.tree.clone()),
        notes: vec![
            "production delete refuses DELETE_UNAVAILABLE pre-destruction in both resolution shapes".to_owned(),
            "retention/reference/delete engine logic covered by central-infra's destructive suite + v29 migration tests".to_owned(),
        ],
        disclosures: vec![
            "live delete awaits the D04 data-plane plumbing (PG role, MinIO delete, repository index rewrite)".to_owned(),
            "slice-d-delete-prune.json is unproducible until then and is absent by design, not by omission".to_owned(),
        ],
        ..ScenarioVerdict::default()
    }
}

// S5: prune mirrors delete. Plan cannot list eligibility without PG,
// so the verb refuses with the documented unavailable code and writes
// no plan file.
pub(crate) fn prune_fail_closed() -> ScenarioVerdict {
    let Some(env) = stand_up() else {
        return skipped(PRODUCTION_TIER_SKIP);
    };

    let planned = env.run(&["backup", "prune", "plan"]);
    assert!(
        planned.reason == destructive::REASON_PRUNE_UNAVAILABLE,
        "plan reason={}",
        planned.reason
    );
    for entry in std::fs::read_dir(&env.work).expect("read work dir") {
        let name = entry.expect("dir entry").file_name();
        assert!(
            !name.to_string_lossy().starts_with(PRUNE_PLAN_PREFIX),
            "refused plan wrote {}",
            name.to_string_lossy()
        );
    }
    assert!(env.consumed().is_empty(), "refused plan spent a grant");
    ScenarioVerdict {
        _tree: Some(env.tree.clone()),
        notes: vec![
            "production prune plan refuses PRUNE_UNAVAILABLE without spending a grant or writing a plan".to_owned(),
            "batching, staleness, and resume logic covered by central-infra's destructive suite + v29 migration tests".to_owned(),
        ],
        disclosures: vec![
            "live prune awaits the same D04 data-plane plumbing as delete".to_owned(),
        ],
        ..ScenarioVerdict::default()
    }
}

// S6: the audit loop for real — genesis, tamper flagging, honest
// repair boundaries — with the evidence artifact carrying the
// verdict.
pub(crate) fn audit_tamper() -> ScenarioVerdict {
    let Some(env) = stand_up() else {
        return skipped(PRODUCTION_TIER_SKIP);
    };
    let protected = env.protected.join(&env.instance_id).join("protected");

    let genesis = env.run(&["local", "audit"]);
    assert!(genesis.exit_code == 0, "genesis: {}", genesis.reason);
    assert!(
        bool_field(&genesis, "baseline_created") && i64_field(&genesis, "tamper_count") == 0,
        "genesis details={}",
        genesis.details
    );

    crate::write_mode(
        protected.join("tls-authority.json"),
        br#"{"ca_cert":"FORGED"}"#,
        0o600,
    )
    .expect("forge protected file");
    let flagged = env.run(&["local", "audit"]);
    assert!(flagged.exit_code == 0, "tamper audit: {}", flagged.reason);
    assert!(
        i64_field(&flagged, "tamper_count") == 1,
        "tamper details={}",
        flagged.details
    );

    // Repair of a modified file: grant, ceremony, removal,
    // re-baseline.
    env.issue(GrantKind::Wipe, "");
    let repaired = env.run(&["local", "audit", "--repair"]);
    assert!(repaired.exit_code == 0, "repair: {}", repaired.reason);
    assert!(
        bool_field(&repaired, "repaired"),
        "repair details={}",
        repaired.details
    );
    let clean = env.run(&["local", "audit"]);
    assert!(
        i64_field(&clean, "tamper_count") == 0,
        "post-repair details={}",
        clean.details
    );

    // Repair of a missing file refuses rather than forgets it: a
    // separate world baselines one file, loses it outside the audit,
    // then repair must refuse without spending its grant.
    let Some(env2) = stand_up() else {
        return skipped(PRODUCTION_TIER_SKIP);
    };
    let protected2 = env2.protected.join(&env2.instance_id).join("protected");
    let genesis2 = env2.run(&["local", "audit"]);
    assert!(genesis2.exit_code == 0, "genesis2: {}", genesis2.reason);
    std::fs::remove_file(protected2.join("tls-authority.json")).expect("remove protected file");
    env2.issue(GrantKind::Wipe, "");
    let refused = env2.run(&["local", "audit", "--repair"]);
    assert!(
        refused.reason == REASON_AUDIT_REPAIR_REFUSED,
        "missing repair reason={}",
        refused.reason
    );
    assert!(env2.consumed().is_empty(), "refused repair spent a grant");
    let raw = env.read_file(AUDIT_EVIDENCE);
    let evidence: serde_json::Value =
        serde_json::from_slice(&raw).expect("evidence does not parse");
    assert!(
        evidence["manifest_valid"].as_bool() == Some(true),
        "evidence reports an invalid manifest"
    );
    ScenarioVerdict {
        evidence_files: Some(vec![AUDIT_EVIDENCE.to_owned()]),
        work_dir: Some(env.work.clone()),
        _tree: Some(env.tree.clone()),
        notes: vec![
            "genesis, modified-file flagging, repair-by-removal, and clean re-audit through the real surface".to_owned(),
        ],
        disclosures: vec![
            "daily cadence awaits the serve ticker (OQ-4); the schedule seam is unit-covered".to_owned(),
        ],
        ..ScenarioVerdict::default()
    }
}

// S7: the deny-safe cycle. Entry (via the B01 hook's own record
// shape), gate refusals through real dispatch, a failing rescue that
// records its attempt and stays denied, and idempotent cleanup across
// attempts.
pub(crate) fn rescue_cycle() -> ScenarioVerdict {
    let Some(env) = stand_up() else {
        return skipped(PRODUCTION_TIER_SKIP);
    };
    let backup_id = env.seal_backup();
    env.install_backup_create(&backup_id);
    let protected = env.protected.join(&env.instance_id).join("protected");
    let deny_safe_store = FileDenySafeStore::new(&protected, env.uid, env.gid);
    deny_safe_store
        .enter_deny_safe(Code::HardExpired.as_str(), OffsetDateTime::now_utc())
        .expect("enter deny-safe");
    env.installed.set(State::HardExpired);

    // The gate refuses a mutating verb through real dispatch with the
    // documented reason, spending no grant. Upstream's probe is
    // `local wipe`, whose fake checkpoint client bypassed the socket;
    // in this port the CLI's `backup-create` hop is refused first and
    // would surface only as WIPE_CHECKPOINT_FAILED — so the gate is
    // probed with `backup delete`, a mutating verb that dials nothing
    // else. Same gate, same documented wire reason, no grant spent.
    env.issue(GrantKind::BackupDelete, "");
    let gated = env.run(&["backup", "delete", &format!("--backup={backup_id}")]);
    assert!(
        gated.reason == advisory::REASON_DENY_SAFE_ACTIVE,
        "gate reason={}",
        gated.reason
    );
    assert!(env.consumed().is_empty(), "gated verb spent a grant");

    // A rescue with a stale candidate: ceremony spends, cleanup runs,
    // the attempt records, and the gate stays active.
    env.candidate
        .set(Outcome::new(State::HardExpired, Code::HardExpired));
    env.issue(GrantKind::SecurityRescue, "");
    let candidate_path = env.work.join("candidate.json");
    crate::write_mode(&candidate_path, br#"{"candidate":"stale"}"#, 0o600)
        .expect("write candidate");
    let failed = env.run(&[
        "local",
        "security",
        "rescue",
        &format!(
            "--advisory={}",
            candidate_path.to_str().expect("candidate utf8")
        ),
    ]);
    assert!(
        failed.reason == advisory::REASON_RESCUE_STAYS_DENIED,
        "rescue reason={}",
        failed.reason
    );
    assert!(
        env.cleanup_calls.load(std::sync::atomic::Ordering::SeqCst) == 1,
        "cleanup calls={}, want 1",
        env.cleanup_calls.load(std::sync::atomic::Ordering::SeqCst)
    );
    let (state, found) =
        load_deny_safe(protected.to_str().expect("protected utf8")).expect("deny-safe record");
    assert!(found, "deny-safe record missing");
    assert!(
        state.cleanup_done && state.rescue_attempts.len() == 1,
        "state={state:?}"
    );

    // Retry with another stale candidate: cleanup is not re-run, the
    // second attempt appends.
    env.issue(GrantKind::SecurityRescue, "");
    let retry = env.run(&[
        "local",
        "security",
        "rescue",
        &format!(
            "--advisory={}",
            candidate_path.to_str().expect("candidate utf8")
        ),
    ]);
    assert!(
        retry.reason == advisory::REASON_RESCUE_STAYS_DENIED,
        "retry reason={}",
        retry.reason
    );
    assert!(
        env.cleanup_calls.load(std::sync::atomic::Ordering::SeqCst) == 1,
        "cleanup calls={}, want 1",
        env.cleanup_calls.load(std::sync::atomic::Ordering::SeqCst)
    );
    let (state, _) =
        load_deny_safe(protected.to_str().expect("protected utf8")).expect("deny-safe record");
    assert!(
        state.rescue_attempts.len() == 2,
        "attempts={}, want 2",
        state.rescue_attempts.len()
    );
    ScenarioVerdict {
        _tree: Some(env.tree.clone()),
        notes: vec![
            "gate refusal, failing rescue with attempt recording, and idempotent cleanup across retries".to_owned(),
            "gate probe uses `backup delete` not `local wipe`: in this port the CLI's backup-create hop is itself gate-refused first, so the documented DENY_SAFE_ACTIVE surfaces verbatim only on a single-verb mutating command".to_owned(),
            "deny-safe entry funnel covered by the advisory app hook tests; the record shape here is identical".to_owned(),
        ],
        disclosures: vec![
            "full exit needs a release-signed current candidate (production release key), unavailable to any test".to_owned(),
            "production cleanup runs lifecycle down; D07 asserts invocation, lifecycle's suite covers down".to_owned(),
        ],
        ..ScenarioVerdict::default()
    }
}

// S8: authority evaluation branches rescue without side effects.
// Current and calm is a no-op success; non-expired denial is the
// wrong-remedy refusal; neither spends a grant nor touches cleanup.
pub(crate) fn rescue_authority() -> ScenarioVerdict {
    let Some(env) = stand_up() else {
        return skipped(PRODUCTION_TIER_SKIP);
    };
    let candidate_path = env.work.join("candidate.json");
    crate::write_mode(&candidate_path, br#"{"candidate":true}"#, 0o600).expect("write candidate");

    env.installed.set(State::Current);
    let noop = env.run(&[
        "local",
        "security",
        "rescue",
        &format!(
            "--advisory={}",
            candidate_path.to_str().expect("candidate utf8")
        ),
    ]);
    assert!(noop.exit_code == 0, "no-op: {}", noop.reason);
    assert!(
        bool_field(&noop, "already_current"),
        "no-op details={}",
        noop.details
    );

    env.installed.set(State::Denied);
    let wrong = env.run(&[
        "local",
        "security",
        "rescue",
        &format!(
            "--advisory={}",
            candidate_path.to_str().expect("candidate utf8")
        ),
    ]);
    assert!(
        wrong.reason == advisory::REASON_RESCUE_NOT_APPLICABLE,
        "reason={}",
        wrong.reason
    );
    assert!(
        env.consumed().is_empty()
            && env.cleanup_calls.load(std::sync::atomic::Ordering::SeqCst) == 0,
        "branched rescue did work"
    );
    env.read_file(RESCUE_EVIDENCE);
    ScenarioVerdict {
        evidence_files: Some(vec![RESCUE_EVIDENCE.to_owned()]),
        work_dir: Some(env.work.clone()),
        _tree: Some(env.tree.clone()),
        ..ScenarioVerdict::default()
    }
}
