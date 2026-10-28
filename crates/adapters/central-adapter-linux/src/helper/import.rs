//! `internal/adapter/authority/helper/import.go` + the import half of
//! `client_linux.go` — the D03 `backup-import` verb: path/target
//! validation, the import-specific ceremony, `bx1` token verification,
//! authenticated decryption, extraction, manifest verification,
//! protected-state bootstrap, restore-plan staging, and — ADR 0034 —
//! the data-plane restore through the composed engine.

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use central_foundation::failure::Failure;
use central_foundation::identity::InstanceId;
use central_infra::destructive;
use central_infra::portable as domain;

use super::PeerIdentity;
use super::export::copy_tree;
use super::grant::CeremonyScope;
use super::portable;
use super::protocol::{Request, Response, read_response, strict_decode, write_request};
use super::restore::RestoreEngineLauncher;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// `ImportRequest` — the bundle file, the token file, and the pinned
/// trust key (hex Ed25519 public key the operator compared out of band
/// at export time).
#[derive(Debug, Clone)]
pub struct ImportRequest {
    /// The ceremony-bound operation (envelope field, not payload).
    pub operation_id: String,
    /// Absolute clean path of the `.tar.gz.bx1` bundle.
    pub bundle_path: String,
    /// Absolute clean path of the `.bx1.json` token.
    pub token_path: String,
    /// 64-hex pinned export public key.
    pub trust_key_hex: String,
}

/// `ImportResult` — the bounded import outcome.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportResult {
    /// The ceremony-bound operation.
    pub operation_id: String,
    /// The imported bundle id.
    pub bundle_id: String,
    /// The instance that produced the bundle.
    pub source_instance_id: String,
    /// The fresh target instance id.
    pub target_instance_id: String,
    /// The spent `bx1` token id.
    pub token_id: String,
    /// Lowercase hex SHA-256 of the encrypted bundle.
    pub bundle_sha256: String,
    /// Staged body count.
    pub body_count: i64,
    /// Lowercase hex SHA-256 of the staged dump (empty when none).
    pub staged_dump_sha256: String,
    /// Lowercase hex SHA-256 of `restore-plan.json`.
    pub restore_plan_sha256: String,
    /// True only after the engine's import receipt validates. A
    /// staging-only run (no engine composed — the fixture tier)
    /// succeeds honestly with false.
    pub data_plane_restored: bool,
    /// RFC 3339 completion timestamp.
    pub completed_at: String,
}

fn trim_ascii(raw: &[u8]) -> &[u8] {
    let s = raw
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let e = raw
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(s, |i| i + 1);
    &raw[s..e.max(s)]
}

/// `ParseImportRequest` — rejects unknown fields so a flag the handler
/// does not understand cannot silently become authority.
pub fn parse_import_request(req: &Request) -> Result<ImportRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing import operation".to_owned());
    }
    let trimmed = trim_ascii(req.payload_bytes());
    if trimmed.is_empty() {
        return Err("helper: import requires a bundle payload".to_owned());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        #[serde(default)]
        bundle_path: String,
        #[serde(default)]
        token_path: String,
        #[serde(default)]
        trust_key_hex: String,
    }
    let payload: Payload =
        strict_decode(trimmed).map_err(|_| "helper: invalid import payload".to_owned())?;
    if payload.bundle_path.is_empty()
        || payload.token_path.is_empty()
        || payload.trust_key_hex.is_empty()
    {
        return Err(
            "helper: import requires bundle_path, token_path, and trust_key_hex".to_owned(),
        );
    }
    Ok(ImportRequest {
        operation_id: req.operation_id.clone(),
        bundle_path: payload.bundle_path,
        token_path: payload.token_path,
        trust_key_hex: payload.trust_key_hex,
    })
}

fn import_response(
    operation_id: &str,
    outcome: &str,
    code: i64,
    reason: &str,
    result: Option<&ImportResult>,
) -> Response {
    let mut resp = Response::new(operation_id, outcome, code, reason);
    if let Some(r) = result {
        resp = resp.with_result(r);
    }
    resp
}

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

/// `importPAMConfirmer` — the D03 ceremony. `None` from
/// [`Self::confirm_backup_import`] means the installed confirmer cannot
/// perform it.
pub trait ImportPamConfirmer: Send + Sync {
    /// `VerifyAndConsume` — minted tokens are one-use.
    fn verify_and_consume(&self, token: &str) -> bool;
    /// `ConfirmBackupImport`.
    fn confirm_backup_import(
        &self,
        _peer: PeerIdentity,
        _deadline: Option<Instant>,
        _scope: &CeremonyScope,
        _operation_id: &str,
    ) -> Option<Result<String, Failure>> {
        None
    }
}

/// `ImportRoots` pins the target instance the import replaces. The
/// target must be fresh (post-D01, never booted); anything else is
/// refused.
#[derive(Debug, Clone, Default)]
pub struct ImportRoots {
    /// The resolved target instance id.
    pub instance_id: String,
    /// The authoritative state root.
    pub state_root: String,
    /// The instance's broker protected dir (`tls-authority.json` must
    /// be absent for a fresh target).
    pub broker_protected_dir: String,
    /// The persistent staging parent (import work area lives under it
    /// and survives the verb).
    pub staging_parent: String,
    /// The instance uid (ownership for installed state).
    pub instance_uid: u32,
    /// See `instance_uid`.
    pub instance_gid: u32,
    /// The instances parent's owner (upstream `ParentUID`).
    pub parent_uid: u32,
    /// See `parent_uid`.
    pub parent_gid: u32,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `ImportHandlerImpl` — performs D03 end to end: ceremony, token
/// verification, decryption, extraction, manifest verification,
/// protected-state bootstrap, the verified restore-plan handoff, and —
/// ADR 0034 — the data-plane restore through the composed engine. The
/// engine is the one deliberately optional seam: a handler built
/// without one stages honestly and reports `data_plane_restored=false`
/// (the fixture tier's whole import story). Production always composes
/// the engine.
pub struct ImportHandlerImpl {
    pam: Option<Box<dyn ImportPamConfirmer>>,
    scope: CeremonyScope,
    roots: ImportRoots,
    engine: Option<Box<dyn RestoreEngineLauncher>>,
    now: fn() -> OffsetDateTime,
}

/// `ImportHandler` — the `Server::import` field type.
pub trait ImportHandler: Send + Sync {
    /// `Import`.
    fn import(&self, deadline: Instant, request: ImportRequest, peer: &PeerIdentity) -> Response;
}

impl ImportHandlerImpl {
    /// `NewImportHandler` — the staging-only composition.
    #[must_use]
    pub fn new(
        pam: Option<Box<dyn ImportPamConfirmer>>,
        scope: CeremonyScope,
        roots: ImportRoots,
    ) -> Self {
        Self {
            pam,
            scope,
            roots,
            engine: None,
            now: OffsetDateTime::now_utc,
        }
    }

    /// `NewImportHandlerWithEngine` — after staging, the verb launches
    /// `central-restore import` for the same operation and reports its
    /// validated outcome. `None` is the staging-only composition, not a
    /// misconfiguration.
    #[must_use]
    pub fn with_engine(
        pam: Option<Box<dyn ImportPamConfirmer>>,
        scope: CeremonyScope,
        roots: ImportRoots,
        engine: Option<Box<dyn RestoreEngineLauncher>>,
    ) -> Self {
        Self {
            engine,
            ..Self::new(pam, scope, roots)
        }
    }

    /// `refuseUnlessFreshTarget` — the D01-first rule: the target must
    /// be a fresh reseed (marker present) that has never booted, never
    /// run, and holds no backups, grants, ceremony state, or earlier
    /// import.
    fn refuse_unless_fresh_target(&self) -> Result<(), ()> {
        let state_root = Path::new(&self.roots.state_root);
        if fs::metadata(state_root.join("reseed.json")).is_err() {
            return Err(());
        }
        for forbidden in [
            state_root.join("import.json"),
            state_root.join("grants"),
            state_root.join("ceremony-mode"),
            state_root.join("export-identity.json"),
            Path::new(&self.roots.broker_protected_dir).join("tls-authority.json"),
        ] {
            // os.Lstat + !IsNotExist — a dangling stat failure is also
            // "initialized", never "fresh".
            if fs::symlink_metadata(&forbidden).is_ok() {
                return Err(());
            }
        }
        for dir in ["lifecycle", "data", "dependencies"] {
            match fs::read_dir(state_root.join(dir)) {
                Ok(entries) => {
                    if entries.take(1).next().is_some() {
                        return Err(());
                    }
                }
                _ => return Err(()),
            }
        }
        // backups/ carries the wipe-time repository binding triple;
        // anything else is initialization.
        let entries = fs::read_dir(state_root.join("backups")).map_err(|_| ())?;
        for entry in entries {
            let entry = entry.map_err(|_| ())?;
            match entry.file_name().to_str() {
                Some("binding.json" | "backup-repository.lock" | "repository-manifest.json") => {}
                _ => return Err(()),
            }
        }
        Ok(())
    }
}

fn ceremony_required(operation_id: &str) -> Response {
    import_response(
        operation_id,
        "denied",
        7,
        domain::REASON_IMPORT_CEREMONY_REQUIRED,
        None,
    )
}

/// `validateImportPaths` — runs before the ceremony: absolute clean
/// regular files for bundle and token, and a 64-hex trust key.
fn validate_import_paths(request: &ImportRequest) -> Result<(), ()> {
    use super::export::CleanLexical as _;
    for path in [&request.bundle_path, &request.token_path] {
        let p = Path::new(path);
        // filepath.IsAbs + filepath.Clean(path) == path.
        if !p.is_absolute() || p != p.clean_lexical().as_path() {
            return Err(());
        }
        match fs::metadata(p) {
            Ok(m) if m.is_file() => {}
            _ => return Err(()),
        }
    }
    let key = domain::hex_decode(&request.trust_key_hex).ok_or(())?;
    if key.len() != 32 {
        return Err(());
    }
    Ok(())
}

impl ImportHandler for ImportHandlerImpl {
    /// `Import` — bundle/token paths and target freshness are validated
    /// before the ceremony; everything after either completes fully or
    /// leaves the target untouched.
    fn import(&self, deadline: Instant, request: ImportRequest, peer: &PeerIdentity) -> Response {
        let op_ok =
            Uuid::parse_str(&request.operation_id).is_ok_and(|u| !u.is_nil()) && peer.pid > 0;
        let seams_ok = self.pam.is_some()
            && !self.scope.instance_id.is_empty()
            && !self.scope.target_id.is_empty()
            && !self.roots.instance_id.is_empty()
            && !self.roots.state_root.is_empty()
            && !self.roots.broker_protected_dir.is_empty()
            && !self.roots.staging_parent.is_empty();
        if !op_ok || !seams_ok {
            return ceremony_required(&request.operation_id);
        }
        if validate_import_paths(&request).is_err() {
            return import_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_IMPORT_INVALID_REQUEST,
                None,
            );
        }
        if self.refuse_unless_fresh_target().is_err() {
            return import_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_IMPORT_TARGET_INIT,
                None,
            );
        }
        let Some(pam) = self.pam.as_deref() else {
            return ceremony_required(&request.operation_id);
        };
        let confirmation = match pam.confirm_backup_import(
            *peer,
            Some(deadline),
            &self.scope,
            &request.operation_id,
        ) {
            Some(Ok(token)) => token,
            _ => {
                return import_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_IMPORT_AUTHORITY_DENIED,
                    None,
                );
            }
        };
        if !pam.verify_and_consume(&confirmation) {
            return import_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_IMPORT_AUTHORITY_DENIED,
                None,
            );
        }
        self.run_import(deadline, &request)
    }
}

impl ImportHandlerImpl {
    fn run_import(&self, deadline: Instant, request: &ImportRequest) -> Response {
        let token_bytes = match fs::read(&request.token_path) {
            Ok(b) if !b.is_empty() && b.len() <= (1 << 20) => b,
            _ => {
                return import_response(
                    &request.operation_id,
                    "denied",
                    2,
                    domain::REASON_IMPORT_TOKEN_INVALID,
                    None,
                );
            }
        };
        let token: domain::Bx1Token = match serde_json::from_slice(&token_bytes) {
            Ok(t) => t,
            Err(_) => {
                return import_response(
                    &request.operation_id,
                    "denied",
                    2,
                    domain::REASON_IMPORT_TOKEN_INVALID,
                    None,
                );
            }
        };
        let bundle_sha = match portable::sha256_file(Path::new(&request.bundle_path)) {
            Ok(s) => s,
            Err(_) => {
                return import_response(
                    &request.operation_id,
                    "denied",
                    2,
                    domain::REASON_IMPORT_BUNDLE_MISMATCH,
                    None,
                );
            }
        };
        if let Err(e) =
            domain::verify_bx1_token(&token, &request.trust_key_hex, &bundle_sha, (self.now)())
        {
            let reason = if e == domain::TokenError::BundleMismatch {
                domain::REASON_IMPORT_BUNDLE_MISMATCH
            } else {
                domain::REASON_IMPORT_TOKEN_INVALID
            };
            return import_response(&request.operation_id, "denied", 2, reason, None);
        }
        let key = domain::b64_url_raw_decode(&token.nonce_b64)
            .and_then(|nonce| domain::derive_bundle_key(&nonce));
        let Some(key) = key else {
            return import_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_IMPORT_TOKEN_INVALID,
                None,
            );
        };
        let stage = match super::export::mkdtemp(
            &self.roots.staging_parent,
            &format!("import-stage-{}-", request.operation_id),
        ) {
            Ok(s) => s,
            Err(_) => {
                return import_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_IMPORT_UNAVAILABLE,
                    None,
                );
            }
        };
        let _stage_guard = RemoveOnDrop(stage.clone());
        let payload = stage.join("payload");
        if fs::create_dir(&payload).is_err() {
            return import_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_IMPORT_UNAVAILABLE,
                None,
            );
        }
        if decrypt_import_bundle(Path::new(&request.bundle_path), &payload, &key).is_err() {
            return import_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_IMPORT_BUNDLE_MISMATCH,
                None,
            );
        }
        let manifest = match portable::verify_extracted_tree(&payload) {
            Ok(m) => m,
            Err(_) => {
                return import_response(
                    &request.operation_id,
                    "denied",
                    2,
                    domain::REASON_IMPORT_BUNDLE_MISMATCH,
                    None,
                );
            }
        };
        if manifest.bundle_id.is_empty() || manifest.instance_id.is_empty() {
            return import_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_IMPORT_BUNDLE_MISMATCH,
                None,
            );
        }
        if self.bootstrap_protected_state(&payload, &manifest).is_err() {
            return import_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_IMPORT_CONFIRM_FAILED,
                None,
            );
        }
        let (plan_sha, dump_sha, body_count) =
            match self.write_restore_plan(&payload, &manifest, &request.operation_id) {
                Ok(t) => t,
                Err(_) => {
                    return import_response(
                        &request.operation_id,
                        "denied",
                        7,
                        domain::REASON_IMPORT_CONFIRM_FAILED,
                        None,
                    );
                }
            };
        let mut staged = ImportResult {
            operation_id: request.operation_id.clone(),
            bundle_id: manifest.bundle_id.clone(),
            source_instance_id: manifest.instance_id.clone(),
            target_instance_id: self.roots.instance_id.clone(),
            token_id: token.token_id.clone(),
            bundle_sha256: bundle_sha,
            body_count,
            staged_dump_sha256: dump_sha,
            restore_plan_sha256: plan_sha,
            data_plane_restored: false,
            completed_at: domain::format_rfc3339_nano((self.now)()),
        };
        let Some(engine) = self.engine.as_ref() else {
            // Staging-only composition (the fixture tier): an honest
            // success whose false flag directs the operator at the
            // data-plane run.
            return import_response(&request.operation_id, "success", 0, "ok", Some(&staged));
        };
        // `runDataPlane` — an engine failure is never reported as
        // success; the staged plan survives under the operation's work
        // dir and the operator re-runs the verb.
        let operation = match Uuid::parse_str(&request.operation_id) {
            Ok(id) if !id.is_nil() => id,
            _ => {
                return import_response(
                    &request.operation_id,
                    "error",
                    6,
                    domain::REASON_IMPORT_CONFIRM_FAILED,
                    None,
                );
            }
        };
        let receipt = match engine.launch_restore_import(deadline, operation) {
            Ok(r) => r,
            Err(_) => {
                return import_response(
                    &request.operation_id,
                    "error",
                    6,
                    domain::REASON_IMPORT_CONFIRM_FAILED,
                    None,
                );
            }
        };
        if receipt.operation_id != request.operation_id
            || receipt.phase.is_empty()
            || receipt.checkpoint.is_empty()
        {
            return import_response(
                &request.operation_id,
                "error",
                6,
                domain::REASON_IMPORT_CONFIRM_FAILED,
                None,
            );
        }
        staged.data_plane_restored = true;
        staged.completed_at = domain::format_rfc3339_nano((self.now)());
        import_response(&request.operation_id, "success", 0, "ok", Some(&staged))
    }

    /// `bootstrapProtectedState` — installs the bundle's operator
    /// document rebound to the fresh target identity, archives the
    /// source's certificates and transition history as reference, and
    /// marks the target imported. Runs only after the token, bundle,
    /// and manifest all verified.
    fn bootstrap_protected_state(
        &self,
        payload: &Path,
        manifest: &domain::ExportManifest,
    ) -> Result<(), ()> {
        let state_root = Path::new(&self.roots.state_root);
        let bundle_config =
            fs::read(payload.join("protected").join("config.json")).map_err(|_| ())?;
        if bundle_config.is_empty() {
            return Err(());
        }
        let target = InstanceId::parse(&self.roots.instance_id).map_err(|_| ())?;
        let rebound = destructive::rewrite_config_for_instance(
            &bundle_config,
            target,
            &self.roots.state_root,
        )
        .map_err(|_| ())?;
        let config_path = state_root.join("config.json");
        let staged_config = PathBuf::from(format!("{}.import", config_path.display()));
        // Upstream removes the staged `.import` file when the chown half
        // of writeImportOwned fails, not just when rename does.
        if write_import_owned(
            &staged_config,
            &rebound,
            self.roots.instance_uid,
            self.roots.instance_gid,
        )
        .is_err()
        {
            let _ = fs::remove_file(&staged_config);
            return Err(());
        }
        if fs::rename(&staged_config, &config_path).is_err() {
            let _ = fs::remove_file(&staged_config);
            return Err(());
        }
        if let Ok(certs) = fs::read(payload.join("protected").join("tls-certs.json")) {
            write_import_owned(
                &state_root.join("imported-tls-certs.json"),
                &certs,
                self.roots.instance_uid,
                self.roots.instance_gid,
            )?;
        }
        if fs::metadata(payload.join("protected").join("lifecycle-records")).is_ok() {
            copy_tree(
                &payload.join("protected").join("lifecycle-records"),
                &state_root.join("lifecycle").join("imported"),
            )?;
        }
        let marker = format!(
            "{{\"bundle_id\":\"{}\",\"data_plane\":\"staged-pending-adr-0034\",\"imported_at\":\"{}\",\"source_instance\":\"{}\",\"target_instance\":\"{}\"}}\n",
            manifest.bundle_id,
            domain::format_rfc3339_nano((self.now)()),
            manifest.instance_id,
            self.roots.instance_id
        );
        write_import_owned(
            &state_root.join(domain::IMPORT_MARKER_FILE_NAME),
            marker.as_bytes(),
            self.roots.instance_uid,
            self.roots.instance_gid,
        )
    }

    /// `writeRestorePlan` — stages the database dump and bodies into the
    /// persistent import work area and writes the machine-readable
    /// handoff for the data-plane follow-up. The work area survives the
    /// verb: it is the follow-up's input.
    fn write_restore_plan(
        &self,
        payload: &Path,
        manifest: &domain::ExportManifest,
        operation_id: &str,
    ) -> Result<(String, String, i64), ()> {
        let work = Path::new(&self.roots.staging_parent).join(format!("import-{operation_id}"));
        fs::create_dir(&work).map_err(|_| ())?;
        let _ = rustix::fs::chmod(&work, rustix::fs::Mode::from_raw_mode(0o700));
        let mut bodies: Vec<domain::ManifestFile> = Vec::new();
        let mut dump: Option<domain::ManifestFile> = None;
        for file in &manifest.files {
            if !file.path.starts_with("backup/") {
                continue;
            }
            if file.path.ends_with("central.dump") && dump.is_none() {
                dump = Some(file.clone());
                continue;
            }
            bodies.push(file.clone());
        }
        let Some(dump) = dump else {
            let _ = fs::remove_dir_all(&work);
            return Err(());
        };
        let db_dir = work.join("db");
        if fs::create_dir(&db_dir).is_err()
            || copy_tree(&payload.join("backup"), &db_dir.join("backup")).is_err()
        {
            let _ = fs::remove_dir_all(&work);
            return Err(());
        }
        // Go strings.TrimPrefix strips exactly one leading "backup/" —
        // trim_start_matches would also eat a "backup/backup/..." prefix.
        let rel = dump.path.strip_prefix("backup/").unwrap_or(&dump.path);
        let plan = domain::RestorePlan {
            bundle_id: manifest.bundle_id.clone(),
            instance_id: manifest.instance_id.clone(),
            token_id: String::new(),
            dump_path: format!("db/backup/{rel}"),
            dump_sha256: dump.sha256.clone(),
            dump_bytes: dump.size,
            expected_body_count: bodies.len() as i64,
            bodies,
            staged_at: domain::format_rfc3339_nano((self.now)()),
        };
        let encoded = serde_json::to_string_pretty(&plan).map_err(|_| ())?;
        let plan_bytes = format!("{encoded}\n");
        if fs::write(work.join(domain::RESTORE_PLAN_FILE_NAME), &plan_bytes).is_err() {
            let _ = fs::remove_dir_all(&work);
            return Err(());
        }
        Ok((
            portable::sha256_hex(plan_bytes.as_bytes()),
            dump.sha256,
            plan.expected_body_count,
        ))
    }
}

/// `decryptImportBundle` — authenticates and decrypts the bundle, then
/// extracts the tar into `payload`. The plaintext tar never touches the
/// operator-visible filesystem: it streams through a staging temp file.
fn decrypt_import_bundle(bundle_path: &Path, payload: &Path, key: &[u8; 32]) -> Result<(), ()> {
    let encrypted = fs::File::open(bundle_path).map_err(|_| ())?;
    let plain_path = payload
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("bundle-plain-{}.tar.gz", Uuid::now_v7()));
    let mut plain = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&plain_path)
        .map_err(|_| ())?;
    let decrypted = portable::decrypt_stream(encrypted, &mut plain, key);
    drop(plain);
    if decrypted.is_err() {
        let _ = fs::remove_file(&plain_path);
        return Err(());
    }
    let archive = fs::File::open(&plain_path).map_err(|_| ())?;
    let extracted = portable::extract_tar_gz(archive, payload);
    let _ = fs::remove_file(&plain_path);
    extracted.map_err(|_| ())
}

/// `writeImportOwned` — install `0600` bytes owned by the instance.
fn write_import_owned(path: &Path, data: &[u8], uid: u32, gid: u32) -> Result<(), ()> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, data))
        .map_err(|_| ())?;
    let _ = rustix::fs::chmod(path, rustix::fs::Mode::from_raw_mode(0o600));
    rustix::fs::chown(
        path,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    )
    .map_err(|_| ())
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Client — `client_linux.go`'s import half.
// ---------------------------------------------------------------------------

/// `ImportClientResult` mirrors the helper's `ImportResult`.
pub type ImportClientResult = ImportResult;

/// `ImportClientError` — only the stable exit class plus a whitelisted
/// reason token cross the boundary.
#[derive(Debug)]
pub struct ImportClientError {
    exit_code: i64,
    reason: String,
}

impl ImportClientError {
    /// The helper's exit class.
    #[must_use]
    pub fn exit_code(&self) -> i64 {
        self.exit_code
    }

    /// The whitelisted helper reason token, or empty.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Test-only constructor for the CLI's closed error-table tests.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(exit_code: i64, reason: &str) -> Self {
        new_import_client_error(exit_code, reason)
    }
}

impl std::fmt::Display for ImportClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("helper: import failed")
    }
}

impl std::error::Error for ImportClientError {}

fn retained_import_reason(reason: &str) -> String {
    match reason {
        r if r == super::delete::DENY_SAFE_ACTIVE_WIRE_REASON
            || r == domain::REASON_IMPORT_TOKEN_INVALID
            || r == domain::REASON_IMPORT_BUNDLE_MISMATCH
            || r == domain::REASON_IMPORT_TARGET_INIT
            || r == domain::REASON_IMPORT_CONFIRM_FAILED
            || r == domain::REASON_IMPORT_CEREMONY_REQUIRED
            || r == domain::REASON_IMPORT_AUTHORITY_DENIED =>
        {
            r.to_owned()
        }
        _ => String::new(),
    }
}

fn new_import_client_error(exit_code: i64, reason: &str) -> ImportClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    ImportClientError {
        exit_code,
        reason: retained_import_reason(reason),
    }
}

/// `ImportClient` — `NewImportClient`'s linux implementation.
pub struct ImportClient {
    socket_path: String,
}

impl ImportClient {
    /// `NewImportClient`.
    #[must_use]
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `Import` — one bounded request/response exchange.
    pub fn import(
        &self,
        operation_id: &str,
        bundle_path: &str,
        token_path: &str,
        trust_key_hex: &str,
    ) -> Result<ImportClientResult, ImportClientError> {
        if self.socket_path.is_empty()
            || operation_id.is_empty()
            || bundle_path.is_empty()
            || token_path.is_empty()
            || trust_key_hex.is_empty()
        {
            return Err(new_import_client_error(3, ""));
        }
        let mut conn = std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(|_| new_import_client_error(3, ""))?;
        let bound = Duration::from_secs(5);
        let _ = conn.set_read_timeout(Some(bound));
        let _ = conn.set_write_timeout(Some(bound));
        #[derive(Serialize)]
        struct Payload<'a> {
            bundle_path: &'a str,
            token_path: &'a str,
            trust_key_hex: &'a str,
        }
        let payload = serde_json::to_string(&Payload {
            bundle_path,
            token_path,
            trust_key_hex,
        })
        .ok()
        .and_then(|s| serde_json::value::RawValue::from_string(s).ok());
        write_request(
            &mut conn,
            &Request {
                operation_id: operation_id.to_owned(),
                verb: super::verb::BACKUP_IMPORT.to_owned(),
                payload,
            },
        )
        .map_err(|_| new_import_client_error(3, ""))?;
        let response = read_response(&mut conn).map_err(|_| new_import_client_error(3, ""))?;
        if response.outcome != "success" || response.exit_code != 0 {
            return Err(new_import_client_error(
                response.exit_code,
                &response.reason,
            ));
        }
        let payload = response
            .result
            .as_ref()
            .map(|r| r.get().as_bytes().to_vec())
            .unwrap_or_default();
        let result: ImportClientResult = super::backup::decode_exact_backup_read_result(&payload)
            .map_err(|_| new_import_client_error(6, ""))?;
        if result.operation_id != operation_id
            || result.bundle_id.is_empty()
            || result.source_instance_id.is_empty()
            || result.target_instance_id.is_empty()
            || result.token_id.is_empty()
            || result.bundle_sha256.len() != 64
            || !result.bundle_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || result.restore_plan_sha256.len() != 64
            || result.completed_at.is_empty()
        {
            return Err(new_import_client_error(6, ""));
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Tests — `import_test.go` coverage: pre-ceremony path validation, the
// fresh-target rule, token/bundle verification failures, and the
// staged-plus-engine happy path.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_INSTANCE: &str = "019b0000-0000-7000-8000-000000000001";
    const SOURCE_INSTANCE: &str = "019b0000-0000-7000-8000-0000000000ff";
    const COMPLETE_CONFIG_FIXTURE: &str = include_str!(
        "../../../../capabilities/central-infra/src/config/testdata/complete-config.json"
    );

    /// `completeConfigFixture` — the on-disk fixture carries no B09
    /// authority fields; production `config.parse` requires them, so
    /// the test fills the budgets, prices, grant TTL, and the profile
    /// signature exactly as `central_infra::config::testutil` does.
    fn complete_config() -> Vec<u8> {
        let mut document: serde_json::Value =
            serde_json::from_slice(COMPLETE_CONFIG_FIXTURE.as_bytes()).expect("fixture decodes");
        let provider = document
            .get_mut("provider")
            .and_then(serde_json::Value::as_object_mut)
            .expect("provider object");
        let fill = |budget: &mut serde_json::Map<String, serde_json::Value>,
                    inputs: &[(&str, u64)]| {
            for (field, value) in inputs {
                budget.insert((*field).to_owned(), serde_json::Value::from(*value));
            }
        };
        fill(
            provider
                .get_mut("default_budget")
                .and_then(serde_json::Value::as_object_mut)
                .expect("default_budget"),
            &[
                ("input_tokens", 10_000),
                ("output_tokens", 1_000),
                ("tool_calls_per_step", 5),
                ("tool_calls_per_run", 20),
                ("wall_time_seconds", 900),
            ],
        );
        fill(
            provider
                .get_mut("hard_budget")
                .and_then(serde_json::Value::as_object_mut)
                .expect("hard_budget"),
            &[
                ("input_tokens", 2_000_000),
                ("output_tokens", 200_000),
                ("tool_calls_per_step", 20),
                ("tool_calls_per_run", 100),
                ("wall_time_seconds", 86_400),
            ],
        );
        provider.insert(
            "input_token_price_micros".to_owned(),
            serde_json::Value::from(1),
        );
        provider.insert(
            "output_token_price_micros".to_owned(),
            serde_json::Value::from(4),
        );
        provider.insert(
            "local_grant_ttl_seconds".to_owned(),
            serde_json::Value::from(900),
        );
        let profile: central_infra::config::ProviderProfile =
            serde_json::from_value(serde_json::Value::Object(provider.clone()))
                .expect("provider decodes");
        provider.insert(
            "signature".to_owned(),
            serde_json::Value::String(profile.canonical_digest()),
        );
        central_foundation::jcs::canonicalize(&document).expect("canonicalize")
    }

    fn tmp(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("central-import-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("tmp");
        dir
    }

    fn peer() -> PeerIdentity {
        PeerIdentity {
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
            pid: std::process::id() as i32,
        }
    }

    fn scope() -> CeremonyScope {
        CeremonyScope {
            instance_id: "default".to_owned(),
            target_id: "postgres:central".to_owned(),
        }
    }

    struct CountingPam {
        calls: AtomicUsize,
        grant: bool,
    }

    impl ImportPamConfirmer for CountingPam {
        fn verify_and_consume(&self, _t: &str) -> bool {
            true
        }
        fn confirm_backup_import(
            &self,
            _p: PeerIdentity,
            _d: Option<Instant>,
            _s: &CeremonyScope,
            _o: &str,
        ) -> Option<Result<String, Failure>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.grant {
                Some(Ok("grant-token".to_owned()))
            } else {
                Some(Err(Failure::denied("pam", "refused")))
            }
        }
    }

    /// `stubLauncher` — records the import launch and returns a valid
    /// receipt.
    struct StubEngine {
        calls: AtomicUsize,
    }

    impl RestoreEngineLauncher for StubEngine {
        fn launch_restore(
            &self,
            _d: Instant,
            _m: &str,
            _o: Uuid,
            _a: Uuid,
        ) -> Result<crate::helper::restore::RestoreEngineReceipt, Failure> {
            Err(Failure::denied("engine", "not an apply"))
        }
        fn launch_restore_import(
            &self,
            _d: Instant,
            operation_id: Uuid,
        ) -> Result<crate::helper::restore::RestoreEngineReceipt, Failure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(crate::helper::restore::RestoreEngineReceipt {
                operation_id: operation_id.to_string(),
                phase: "applied".to_owned(),
                checkpoint: "checkpoint".to_owned(),
            })
        }
    }

    /// The fresh-target fixture: `reseed.json` present, the four runtime
    /// dirs empty, `backups/` holding only the wipe-time binding
    /// triple, and no `tls-authority.json` under the broker root.
    fn fresh_target(tag: &str) -> (PathBuf, ImportRoots) {
        let base = tmp(tag);
        let state = base.join("state");
        fs::create_dir_all(&state).expect("state");
        fs::write(state.join("reseed.json"), b"{\"reseeded\":true}").expect("reseed");
        for d in ["lifecycle", "data", "dependencies", "backups"] {
            fs::create_dir_all(state.join(d)).expect("{d}");
        }
        for f in [
            "binding.json",
            "backup-repository.lock",
            "repository-manifest.json",
        ] {
            fs::write(state.join("backups").join(f), b"{}").expect("{f}");
        }
        let broker = base.join("broker").join("protected");
        fs::create_dir_all(&broker).expect("broker");
        let staging = base.join("staging");
        fs::create_dir_all(&staging).expect("staging");
        let roots = ImportRoots {
            instance_id: TEST_INSTANCE.to_owned(),
            state_root: state.to_string_lossy().into_owned(),
            broker_protected_dir: broker.to_string_lossy().into_owned(),
            staging_parent: staging.to_string_lossy().into_owned(),
            instance_uid: rustix::process::geteuid().as_raw(),
            instance_gid: rustix::process::getegid().as_raw(),
            parent_uid: 0,
            parent_gid: 0,
        };
        (base, roots)
    }

    /// `makeBundle` — builds the export-side artifacts directly through
    /// the same domain + adapter primitives the exporter uses, so the
    /// test exercises the importer against a truly self-verified
    /// bundle, not a fixture that merely looks like one.
    fn make_bundle(tag: &str) -> (PathBuf, PathBuf, domain::Bx1Token) {
        let dir = tmp(&format!("{tag}-bundle"));
        let payload = dir.join("payload");
        fs::create_dir_all(payload.join("backup").join("objects")).expect("mk");
        fs::create_dir_all(payload.join("protected")).expect("mk");
        fs::write(payload.join("backup").join("central.dump"), b"pgdump-body").expect("w");
        fs::write(
            payload.join("backup").join("objects").join("body-1"),
            b"body",
        )
        .expect("w");
        fs::write(
            payload.join("protected").join("config.json"),
            complete_config(),
        )
        .expect("w");
        fs::write(
            payload.join("protected").join("tls-certs.json"),
            b"{\"x\":1}",
        )
        .expect("w");
        let bundle_id = Uuid::now_v7().to_string();
        let mut manifest = domain::ExportManifest {
            bundle_id: bundle_id.clone(),
            instance_id: SOURCE_INSTANCE.to_owned(),
            created_at: domain::format_rfc3339_nano(OffsetDateTime::now_utc()),
            purpose: domain::EXPORT_PURPOSE.to_owned(),
            files: Vec::new(),
            body_count: 0,
        };
        for rel in [
            "backup/central.dump",
            "backup/objects/body-1",
            "protected/config.json",
            "protected/tls-certs.json",
        ] {
            let raw = fs::read(payload.join(rel)).expect("r");
            manifest.files.push(domain::ManifestFile {
                path: rel.to_owned(),
                size: raw.len() as i64,
                sha256: portable::sha256_hex(&raw),
            });
        }
        manifest.body_count = 2;
        let encoded = serde_json::to_string_pretty(&manifest).expect("manifest");
        fs::write(payload.join("manifest.json"), format!("{encoded}\n")).expect("manifest w");
        // Archive + encrypt exactly as the exporter does.
        let tar_path = dir.join("bundle.tar.gz");
        let created = domain::parse_rfc3339(&manifest.created_at).expect("created");
        let tar = fs::File::create(&tar_path).expect("tar");
        portable::build_tar_gz(&payload, tar, created).expect("tar gz");
        let nonce = [0x0bu8; 32];
        let key = domain::derive_bundle_key(&nonce).expect("key");
        let bundle_path = dir.join("central-export.bx1");
        {
            let mut plain = fs::File::open(&tar_path).expect("open tar");
            let mut out = fs::File::create(&bundle_path).expect("bundle");
            portable::encrypt_stream(&mut plain, &mut out, &key).expect("encrypt");
        }
        let bundle_sha = portable::sha256_file(&bundle_path).expect("sha");
        let seed = [0x2au8; 32];
        let token = domain::issue_bx1_token(
            &seed,
            &Uuid::now_v7().to_string(),
            &bundle_sha,
            SOURCE_INSTANCE,
            domain::EXPORT_PURPOSE,
            OffsetDateTime::now_utc(),
            domain::TOKEN_EXPIRY_SECONDS,
            &nonce,
        )
        .expect("token");
        let token_path = dir.join("central-export.bx1.json");
        let encoded = serde_json::to_string_pretty(&token).expect("token json");
        fs::write(&token_path, format!("{encoded}\n")).expect("token w");
        (bundle_path, token_path, token)
    }

    fn request(bundle: &Path, token: &Path, trust: &str) -> ImportRequest {
        ImportRequest {
            operation_id: Uuid::now_v7().to_string(),
            bundle_path: bundle.to_string_lossy().into_owned(),
            token_path: token.to_string_lossy().into_owned(),
            trust_key_hex: trust.to_owned(),
        }
    }

    fn decode_result(resp: &Response) -> ImportResult {
        serde_json::from_str(resp.result.as_ref().expect("no result").get()).expect("decode")
    }

    /// `TestImportRejectsMalformedPathsBeforeCeremony` — relative,
    /// unclean, missing, or non-file paths and bad trust keys deny with
    /// `INVALID_IMPORT_REQUEST` and never reach the ceremony.
    #[test]
    fn import_rejects_bad_paths_before_ceremony() {
        let (_base, roots) = fresh_target("badpaths");
        let (bundle, token_path, token) = make_bundle("badpaths");
        let pam = CountingPam {
            calls: AtomicUsize::new(0),
            grant: true,
        };
        let handler = ImportHandlerImpl::new(Some(Box::new(pam)), scope(), roots);
        let deadline = Instant::now() + Duration::from_secs(60);
        let good = request(&bundle, &token_path, &token.public_key_hex);
        for bad in [
            ImportRequest {
                bundle_path: "relative/bundle.bx1".to_owned(),
                ..good.clone()
            },
            ImportRequest {
                bundle_path: "/definitely/missing.bx1".to_owned(),
                ..good.clone()
            },
            ImportRequest {
                token_path: "/tmp/../etc/passwd".to_owned(),
                ..good.clone()
            },
            ImportRequest {
                trust_key_hex: "not-hex".to_owned(),
                ..good.clone()
            },
            ImportRequest {
                trust_key_hex: "abcd".to_owned(),
                ..good.clone()
            },
        ] {
            let resp = handler.import(deadline, bad, &peer());
            assert_eq!(resp.outcome, "denied");
            assert_eq!(resp.reason, domain::REASON_IMPORT_INVALID_REQUEST);
        }
    }

    /// `TestImportRejectsInitializedTarget` — any trace of prior
    /// initialization (a lifecycle entry here) denies with
    /// `IMPORT_TARGET_INITIALIZED` before the ceremony.
    #[test]
    fn import_rejects_initialized_target() {
        let (_base, roots) = fresh_target("inittgt");
        let (bundle, token_path, token) = make_bundle("inittgt");
        fs::write(
            Path::new(&roots.state_root).join("lifecycle").join("boot"),
            b"x",
        )
        .expect("mark");
        let handler = ImportHandlerImpl::new(
            Some(Box::new(CountingPam {
                calls: AtomicUsize::new(0),
                grant: true,
            })),
            scope(),
            roots,
        );
        let resp = handler.import(
            Instant::now() + Duration::from_secs(60),
            request(&bundle, &token_path, &token.public_key_hex),
            &peer(),
        );
        assert_eq!(resp.outcome, "denied");
        assert_eq!(resp.reason, domain::REASON_IMPORT_TARGET_INIT);
    }

    /// `TestImportRejectsTokenMismatches` — a wrong trust key is
    /// `IMPORT_TOKEN_INVALID`; a tampered bundle is
    /// `IMPORT_BUNDLE_MISMATCH` (the token's pinned digest fails first).
    #[test]
    fn import_rejects_wrong_key_and_tampered_bundle() {
        let (_base, roots) = fresh_target("token");
        let (bundle, token_path, token) = make_bundle("token");
        let handler = ImportHandlerImpl::new(
            Some(Box::new(CountingPam {
                calls: AtomicUsize::new(0),
                grant: true,
            })),
            scope(),
            roots,
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        // Wrong trust key: the signature check fails.
        let resp = handler.import(
            deadline,
            request(&bundle, &token_path, &domain::hex_encode(&[0x99; 32])),
            &peer(),
        );
        assert_eq!(resp.outcome, "denied");
        assert_eq!(resp.reason, domain::REASON_IMPORT_TOKEN_INVALID);
        // Tampered bundle: the digest no longer matches the token pin.
        let tampered = tmp("token-tampered").join("bundle.bx1");
        let mut bytes = fs::read(&bundle).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&tampered, &bytes).expect("write");
        let resp = handler.import(
            deadline,
            request(&tampered, &token_path, &token.public_key_hex),
            &peer(),
        );
        assert_eq!(resp.outcome, "denied");
        assert_eq!(resp.reason, domain::REASON_IMPORT_BUNDLE_MISMATCH);
    }

    /// `TestImportRoundTrip` — staging succeeds, the plan + marker
    /// land, and the composed engine is launched for the same
    /// operation; the receipt is validated, so `data_plane_restored`
    /// is honest.
    #[test]
    fn import_round_trip_bootstraps_and_launches_engine() {
        let (base, roots) = fresh_target("roundtrip");
        let (bundle, token_path, token) = make_bundle("roundtrip");
        let state_root = roots.state_root.clone();
        let staging_parent = roots.staging_parent.clone();
        let engine = StubEngine {
            calls: AtomicUsize::new(0),
        };
        let handler = ImportHandlerImpl::with_engine(
            Some(Box::new(CountingPam {
                calls: AtomicUsize::new(0),
                grant: true,
            })),
            scope(),
            roots,
            Some(Box::new(engine)),
        );
        let req = request(&bundle, &token_path, &token.public_key_hex);
        let op = req.operation_id.clone();
        let resp = handler.import(Instant::now() + Duration::from_secs(300), req, &peer());
        assert_eq!(resp.outcome, "success", "reason={}", resp.reason);
        assert_eq!(resp.exit_code, 0);
        let result = decode_result(&resp);
        assert_eq!(result.operation_id, op);
        assert_eq!(result.source_instance_id, SOURCE_INSTANCE);
        assert_eq!(result.target_instance_id, TEST_INSTANCE);
        assert_eq!(result.body_count, 1);
        assert!(result.data_plane_restored);
        assert_eq!(result.staged_dump_sha256.len(), 64);
        assert_eq!(result.restore_plan_sha256.len(), 64);
        // Bootstrap side effects: rebound config, import marker, and
        // the persisted plan + dump inside the operation's work dir.
        let state = Path::new(&state_root);
        assert!(state.join("import.json").exists());
        let rebound = fs::read_to_string(state.join("config.json")).expect("config");
        assert!(rebound.contains(TEST_INSTANCE));
        let work = Path::new(&staging_parent).join(format!("import-{op}"));
        assert!(work.join(domain::RESTORE_PLAN_FILE_NAME).exists());
        assert!(work.join("db").join("backup").join("central.dump").exists());
        let _ = base;
    }

    /// `TestImportStagingOnlyComposition` — without an engine the verb
    /// still completes honestly with `data_plane_restored=false`.
    #[test]
    fn import_staging_only_succeeds_with_data_plane_false() {
        let (_base, roots) = fresh_target("staged");
        let (bundle, token_path, token) = make_bundle("staged");
        let handler = ImportHandlerImpl::new(
            Some(Box::new(CountingPam {
                calls: AtomicUsize::new(0),
                grant: true,
            })),
            scope(),
            roots,
        );
        let resp = handler.import(
            Instant::now() + Duration::from_secs(300),
            request(&bundle, &token_path, &token.public_key_hex),
            &peer(),
        );
        assert_eq!(resp.outcome, "success");
        let result = decode_result(&resp);
        assert!(!result.data_plane_restored);
    }
}
