//! `internal/adapter/authority/helper/export.go` + the export half of
//! `client_linux.go` — the D02 `backup-export` verb: out-dir
//! validation, the export-specific ceremony, sealed-backup resolution,
//! protected-subset collection + secret scan, export-identity
//! load-or-mint, deterministic archiving, authenticated encryption,
//! `bx1` token issuance, ownership handoff, and self-verification.

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use central_foundation::failure::Failure;
use central_infra::portable as domain;

use super::PeerIdentity;
use super::grant::CeremonyScope;
use super::portable::{self, PortableError};
use super::protocol::{Request, Response, read_response, strict_decode, write_request};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// `ExportRequest` — names the backup (empty resolves the single sealed
/// candidate) and the operator output directory.
#[derive(Debug, Clone)]
pub struct ExportRequest {
    /// The ceremony-bound operation (envelope field, not payload).
    pub operation_id: String,
    /// The explicit sealed backup id, or empty for single-candidate
    /// resolution.
    pub backup_id: String,
    /// The operator's absolute, clean output directory.
    pub out_dir: String,
}

/// `ExportResult` — the bounded export outcome: identities, digests,
/// and file names only. The bundle and token paths are derived by the
/// CLI from `out_dir` + these names, never carried as absolute paths.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportResult {
    /// The ceremony-bound operation.
    pub operation_id: String,
    /// Freshly minted bundle id.
    pub bundle_id: String,
    /// Source sealed backup id.
    pub backup_id: String,
    /// Source instance id.
    pub instance_id: String,
    /// Lowercase hex SHA-256 of the encrypted bundle.
    pub bundle_sha256: String,
    /// `central-export-<bundle-id>.tar.gz.bx1` basename.
    pub bundle_file: String,
    /// `central-export-<bundle-id>.bx1.json` basename.
    pub token_file: String,
    /// Issued `bx1` token id.
    pub token_id: String,
    /// True when this operation minted the export identity.
    pub identity_created: bool,
    /// Lowercase hex Ed25519 export verifying key.
    pub public_key_hex: String,
    /// Files staged under `backup/`.
    pub body_count: i64,
    /// Encrypted bundle byte length.
    pub bundle_bytes: i64,
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

/// `ParseExportRequest` — rejects unknown fields so a flag the handler
/// does not understand cannot silently become authority.
pub fn parse_export_request(req: &Request) -> Result<ExportRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing export operation".to_owned());
    }
    let trimmed = trim_ascii(req.payload_bytes());
    if trimmed.is_empty() {
        return Err("helper: export requires an out_dir payload".to_owned());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        #[serde(default)]
        backup_id: String,
        #[serde(default)]
        out_dir: String,
    }
    let payload: Payload =
        strict_decode(trimmed).map_err(|_| "helper: invalid export payload".to_owned())?;
    if payload.out_dir.is_empty() {
        return Err("helper: export requires out_dir".to_owned());
    }
    Ok(ExportRequest {
        operation_id: req.operation_id.clone(),
        backup_id: payload.backup_id,
        out_dir: payload.out_dir,
    })
}

fn export_response(
    operation_id: &str,
    outcome: &str,
    code: i64,
    reason: &str,
    result: Option<&ExportResult>,
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

/// `exportPAMConfirmer` — the D02 ceremony. `None` from
/// [`Self::confirm_backup_export`] means the installed confirmer cannot
/// perform it rather than falling back to any other destructive ceremony.
pub trait ExportPamConfirmer: Send + Sync {
    /// `VerifyAndConsume` — minted tokens are one-use.
    fn verify_and_consume(&self, token: &str) -> bool;
    /// `ConfirmBackupExport`.
    fn confirm_backup_export(
        &self,
        _peer: PeerIdentity,
        _deadline: Option<Instant>,
        _scope: &CeremonyScope,
        _operation_id: &str,
    ) -> Option<Result<String, Failure>> {
        None
    }
}

/// `exportBackupSource` — lists sealed backups and stages one verified
/// backup tree for archiving. Production opens the read-only backup
/// repository; tests substitute a fixture source.
pub trait ExportBackupSource: Send + Sync {
    /// `ListSealedBackupIDs`.
    fn list_sealed_backup_ids(&self) -> Result<Vec<Uuid>, Failure>;
    /// `VerifyAndStageBackup` — verifies the backup's seal and copies
    /// its whole sealed tree under `stage_dir`.
    fn verify_and_stage_backup(&self, backup_id: Uuid, stage_dir: &Path) -> Result<(), Failure>;
}

/// `ExportRoots` pins the hierarchies an export reads. The instance
/// identity, state root, and broker protected dir come from the
/// resolved composition, never from the request.
#[derive(Debug, Clone, Default)]
pub struct ExportRoots {
    /// The resolved instance id.
    pub instance_id: String,
    /// The authoritative state root.
    pub state_root: String,
    /// The instance's broker protected dir (`tls-authority.json`).
    pub broker_protected_dir: String,
    /// The instances parent's owner (upstream `InstancesParentUID`).
    pub instances_parent_uid: u32,
    /// See `instances_parent_uid`.
    pub instances_parent_gid: u32,
    /// The instance uid (file ownership for minted state).
    pub instance_uid: u32,
    /// See `instance_uid`.
    pub instance_gid: u32,
    /// The transient staging parent (state root's parent).
    pub staging_parent: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `ExportHandlerImpl` — performs D02.
pub struct ExportHandlerImpl {
    pam: Option<Box<dyn ExportPamConfirmer>>,
    scope: CeremonyScope,
    roots: ExportRoots,
    source: Option<Box<dyn ExportBackupSource>>,
    new_id: fn() -> Uuid,
    now: fn() -> OffsetDateTime,
}

/// `ExportHandler` — the `Server::export` field type.
pub trait ExportHandler: Send + Sync {
    /// `Export`.
    fn export(&self, deadline: Instant, request: ExportRequest, peer: &PeerIdentity) -> Response;
}

impl ExportHandlerImpl {
    /// `NewExportHandler` — any `None` seam refuses every request.
    #[must_use]
    pub fn new(
        pam: Option<Box<dyn ExportPamConfirmer>>,
        scope: CeremonyScope,
        roots: ExportRoots,
        source: Option<Box<dyn ExportBackupSource>>,
    ) -> Self {
        Self {
            pam,
            scope,
            roots,
            source,
            new_id: Uuid::now_v7,
            now: OffsetDateTime::now_utc,
        }
    }

    /// `resolveBackup` — an explicit id must name a sealed backup; with
    /// no explicit id exactly one candidate must exist.
    fn resolve_backup(&self, request: &ExportRequest) -> Result<Uuid, Response> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| ceremony_required(&request.operation_id))?;
        let sealed = source.list_sealed_backup_ids().map_err(|_| {
            export_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_EXPORT_BACKUP_UNSEALED,
                None,
            )
        })?;
        if !request.backup_id.is_empty() {
            let want = match Uuid::parse_str(&request.backup_id) {
                Ok(id) if !id.is_nil() => id,
                _ => {
                    return Err(export_response(
                        &request.operation_id,
                        "denied",
                        2,
                        domain::REASON_EXPORT_INVALID_REQUEST,
                        None,
                    ));
                }
            };
            if sealed.contains(&want) {
                return Ok(want);
            }
            return Err(export_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_EXPORT_BACKUP_UNSEALED,
                None,
            ));
        }
        match sealed.len() {
            0 => Err(export_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_EXPORT_NO_BACKUP,
                None,
            )),
            1 => Ok(sealed[0]),
            _ => Err(export_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_EXPORT_BACKUP_AMBIGUOUS,
                None,
            )),
        }
    }
}

fn ceremony_required(operation_id: &str) -> Response {
    export_response(
        operation_id,
        "denied",
        7,
        domain::REASON_EXPORT_CEREMONY_REQUIRED,
        None,
    )
}

fn unavailable(operation_id: &str) -> Response {
    export_response(
        operation_id,
        "denied",
        7,
        domain::REASON_EXPORT_UNAVAILABLE,
        None,
    )
}

/// `validateExportOutDir` — runs before the ceremony: absolute, clean,
/// an existing directory.
fn validate_export_out_dir(out: &str) -> Result<(), ()> {
    let path = Path::new(out);
    if !path.is_absolute() || path != path.clean_lexical() {
        return Err(());
    }
    match fs::metadata(path) {
        Ok(m) if m.is_dir() => Ok(()),
        _ => Err(()),
    }
}

pub(crate) trait CleanLexical {
    fn clean_lexical(&self) -> PathBuf;
}

impl CleanLexical for Path {
    /// `filepath.Clean` — collapses `.`, `..`, and duplicate slashes
    /// lexically (never touching the filesystem).
    fn clean_lexical(&self) -> PathBuf {
        let mut out: Vec<&std::ffi::OsStr> = Vec::new();
        for comp in self.components() {
            match comp {
                std::path::Component::ParentDir => {
                    if out.last().is_some_and(|c| *c == std::ffi::OsStr::new(".."))
                        || out.is_empty()
                    {
                        out.push(std::ffi::OsStr::new(".."));
                    } else if out.last() == Some(&std::ffi::OsStr::new("/")) {
                        // filepath.Clean: `..` cannot ascend past the root.
                    } else {
                        out.pop();
                    }
                }
                std::path::Component::CurDir => {}
                std::path::Component::RootDir => out.push(std::ffi::OsStr::new("/")),
                std::path::Component::Normal(s) => out.push(s),
                std::path::Component::Prefix(_) => {}
            }
        }
        out.iter().collect()
    }
}

/// `os.MkdirTemp` — create a `0700` directory under `parent` with the
/// `prefix + random-hex` name; retries on collision.
pub(crate) fn mkdtemp(parent: &str, prefix: &str) -> std::io::Result<PathBuf> {
    for _ in 0..16 {
        let mut raw = [0u8; 8];
        rustix::rand::getrandom(&mut raw, rustix::rand::GetRandomFlags::empty())?;
        let dir = Path::new(parent).join(format!("{prefix}{}", domain::hex_encode(&raw)));
        match fs::create_dir(&dir) {
            Ok(()) => {
                rustix::fs::chmod(&dir, rustix::fs::Mode::from_raw_mode(0o700))?;
                return Ok(dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "mkdtemp exhausted",
    ))
}

fn remove_partial(paths: &[&Path]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}

/// `subtle.ConstantTimeCompare` — the derived key is proven against the
/// issued token's own nonce before success is reported.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

impl ExportHandler for ExportHandlerImpl {
    /// `Export` — the output directory is validated before the ceremony;
    /// everything after either completes fully or removes its partial
    /// artifacts.
    fn export(&self, _deadline: Instant, request: ExportRequest, peer: &PeerIdentity) -> Response {
        let op_ok =
            Uuid::parse_str(&request.operation_id).is_ok_and(|u| !u.is_nil()) && peer.pid > 0;
        let seams_ok = self.pam.is_some()
            && self.source.is_some()
            && !self.scope.instance_id.is_empty()
            && !self.scope.target_id.is_empty()
            && !self.roots.instance_id.is_empty()
            && !self.roots.state_root.is_empty()
            && !self.roots.broker_protected_dir.is_empty()
            && !self.roots.staging_parent.is_empty();
        if !op_ok || !seams_ok {
            return ceremony_required(&request.operation_id);
        }
        if validate_export_out_dir(&request.out_dir).is_err() {
            return export_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_EXPORT_OUT_INVALID,
                None,
            );
        }
        let Some(pam) = self.pam.as_deref() else {
            return ceremony_required(&request.operation_id);
        };
        let confirmation = match pam.confirm_backup_export(
            *peer,
            Some(_deadline),
            &self.scope,
            &request.operation_id,
        ) {
            Some(Ok(token)) => token,
            _ => {
                return export_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_EXPORT_AUTHORITY_DENIED,
                    None,
                );
            }
        };
        if !pam.verify_and_consume(&confirmation) {
            return export_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_EXPORT_AUTHORITY_DENIED,
                None,
            );
        }
        let backup_id = match self.resolve_backup(&request) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
        self.run_export(&request, peer, backup_id)
    }
}

impl ExportHandlerImpl {
    #[allow(clippy::too_many_lines)]
    fn run_export(
        &self,
        request: &ExportRequest,
        peer: &PeerIdentity,
        backup_id: Uuid,
    ) -> Response {
        let bundle_id = (self.new_id)();
        if bundle_id.is_nil() {
            return unavailable(&request.operation_id);
        }
        let stage = match mkdtemp(
            &self.roots.staging_parent,
            &format!("export-stage-{}-", request.operation_id),
        ) {
            Ok(s) => s,
            Err(_) => return unavailable(&request.operation_id),
        };
        let _stage_guard = RemoveOnDrop(stage.clone());
        let payload = stage.join("payload");
        if fs::create_dir(&payload).is_err() {
            return unavailable(&request.operation_id);
        }
        let backup_stage = payload.join("backup");
        if fs::create_dir(&backup_stage).is_err() {
            return unavailable(&request.operation_id);
        }
        let Some(source) = self.source.as_ref() else {
            return unavailable(&request.operation_id);
        };
        if source
            .verify_and_stage_backup(backup_id, &backup_stage)
            .is_err()
        {
            return export_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_EXPORT_BACKUP_UNSEALED,
                None,
            );
        }
        let protected_stage = payload.join("protected");
        if self.collect_protected_subset(&protected_stage).is_err()
            || portable::scan_protected_subset(&protected_stage).is_err()
        {
            return unavailable(&request.operation_id);
        }
        let (identity, identity_created) = match portable::load_or_mint_export_identity(
            &Path::new(&self.roots.state_root).join("export-identity.json"),
            self.roots.instance_uid,
            self.roots.instance_gid,
            (self.now)(),
        ) {
            Ok(pair) => pair,
            Err(_) => {
                return export_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_EXPORT_IDENTITY_FAILED,
                    None,
                );
            }
        };
        let manifest = match write_export_manifest(
            &payload,
            &bundle_id.to_string(),
            &self.roots.instance_id,
            (self.now)(),
        ) {
            Ok(m) => m,
            Err(_) => return unavailable(&request.operation_id),
        };
        // Archive to a staging temp file first: the bundle bytes hash
        // before anything lands in the operator directory.
        let plain_path = stage.join("bundle.tar.gz");
        let created_at =
            domain::parse_rfc3339(&manifest.created_at).unwrap_or_else(OffsetDateTime::now_utc);
        let tar_ok = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&plain_path)
            .map_err(|_| ())
            .and_then(|f| portable::build_tar_gz(&payload, f, created_at).map_err(|_| ()));
        if tar_ok.is_err() {
            return unavailable(&request.operation_id);
        }
        let mut nonce = [0u8; 32];
        if rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty()).is_err() {
            return unavailable(&request.operation_id);
        }
        let Some(key) = domain::derive_bundle_key(&nonce) else {
            return unavailable(&request.operation_id);
        };
        let bundle_file = format!("central-export-{bundle_id}.tar.gz.bx1");
        let token_file = format!("central-export-{bundle_id}.bx1.json");
        let out_dir = Path::new(&request.out_dir);
        let bundle_path = out_dir.join(&bundle_file);
        let token_path = out_dir.join(&token_file);
        let partial = [&*bundle_path, &*token_path];
        // Encrypt O_EXCL under the operator directory; every failure
        // below removes the partial artifacts upstream's
        // `removePartialExport` removes.
        let encrypt = || -> Result<(), ()> {
            let mut plain = fs::File::open(&plain_path).map_err(|_| ())?;
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&bundle_path)
                .map_err(|_| ())?;
            portable::encrypt_stream(&mut plain, &mut out, &key).map_err(|_| ())?;
            out.sync_all().map_err(|_| ())
        };
        if encrypt().is_err() {
            remove_partial(&partial);
            return unavailable(&request.operation_id);
        }
        let bundle_sha = match portable::sha256_file(&bundle_path) {
            Ok(s) => s,
            Err(_) => {
                remove_partial(&partial);
                return unavailable(&request.operation_id);
            }
        };
        let bundle_bytes = fs::metadata(&bundle_path).map(|m| m.len()).unwrap_or(0);
        let Some(seed) = domain::hex_decode(&identity.private_seed_hex) else {
            remove_partial(&partial);
            return export_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_EXPORT_IDENTITY_FAILED,
                None,
            );
        };
        if seed.len() != 32 {
            remove_partial(&partial);
            return export_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_EXPORT_IDENTITY_FAILED,
                None,
            );
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        let token_id = (self.new_id)();
        if token_id.is_nil() {
            remove_partial(&partial);
            return unavailable(&request.operation_id);
        }
        let Some(token) = domain::issue_bx1_token(
            &seed_arr,
            &token_id.to_string(),
            &bundle_sha,
            &self.roots.instance_id,
            domain::EXPORT_PURPOSE,
            (self.now)(),
            domain::TOKEN_EXPIRY_SECONDS,
            &nonce,
        ) else {
            remove_partial(&partial);
            return export_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_EXPORT_IDENTITY_FAILED,
                None,
            );
        };
        let token_bytes = serde_json::to_string_pretty(&token).unwrap_or_default();
        if fs::write(&token_path, format!("{token_bytes}\n")).is_err() {
            remove_partial(&partial);
            return unavailable(&request.operation_id);
        }
        // Handoff: the operator owns the outputs — root-written,
        // peer-owned.
        for path in [&bundle_path, &token_path] {
            if rustix::fs::chown(
                path,
                Some(rustix::fs::Uid::from_raw(peer.uid)),
                Some(rustix::fs::Gid::from_raw(peer.gid)),
            )
            .is_err()
            {
                remove_partial(&partial);
                return unavailable(&request.operation_id);
            }
        }
        // `selfVerifyExport` — re-derive the key from the token's own
        // nonce and authenticate every segment before reporting success.
        let self_ok = (|| -> Result<(), PortableError> {
            let decoded = domain::b64_url_raw_decode(&token.nonce_b64)
                .ok_or_else(|| PortableError("nonce".to_owned()))?;
            let derived = domain::derive_bundle_key(&decoded)
                .ok_or_else(|| PortableError("derive".to_owned()))?;
            if !ct_eq(&derived, &key) {
                return Err(PortableError("key mismatch".to_owned()));
            }
            let file =
                fs::File::open(&bundle_path).map_err(|_| PortableError("open".to_owned()))?;
            portable::decrypt_stream(file, std::io::sink(), &derived)
        })();
        if self_ok.is_err() {
            remove_partial(&partial);
            return export_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_EXPORT_SELF_VERIFY_FAILED,
                None,
            );
        }
        export_response(
            &request.operation_id,
            "success",
            0,
            "ok",
            Some(&ExportResult {
                operation_id: request.operation_id.clone(),
                bundle_id: bundle_id.to_string(),
                backup_id: backup_id.to_string(),
                instance_id: self.roots.instance_id.clone(),
                bundle_sha256: bundle_sha,
                bundle_file,
                token_file,
                token_id: token_id.to_string(),
                identity_created,
                public_key_hex: identity.public_key_hex,
                body_count: manifest.body_count,
                bundle_bytes: bundle_bytes as i64,
                completed_at: domain::format_rfc3339_nano((self.now)()),
            }),
        )
    }

    /// `collectProtectedSubset` — the exportable protected-state subset:
    /// `config.json`, the TLS CA/leaf CERTIFICATES (never the keys), the
    /// lifecycle transition records, the instance identity, and the
    /// reseed marker when present. Trust material is never staged; the
    /// post-stage scan enforces that.
    fn collect_protected_subset(&self, dst: &Path) -> Result<(), ()> {
        fs::create_dir(dst).map_err(|_| ())?;
        let config =
            fs::read(Path::new(&self.roots.state_root).join("config.json")).map_err(|_| ())?;
        if config.is_empty() {
            return Err(());
        }
        fs::write(dst.join("config.json"), &config).map_err(|_| ())?;
        self.collect_tls_certs(dst)?;
        // The journal lives beside the protected dir. Only
        // lifecycle-records/ is collected: its record shape carries no
        // secrets, while authority-records/ has no verified shape.
        let lifecycle_src = Path::new(&self.roots.broker_protected_dir)
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join("lifecycle-records");
        if fs::symlink_metadata(&lifecycle_src)
            .map(|m| m.is_dir() && !m.file_type().is_symlink())
            .unwrap_or(false)
        {
            copy_tree(&lifecycle_src, &dst.join("lifecycle-records"))?;
        }
        let instance_doc = format!("{{\"instance_id\":\"{}\"}}\n", self.roots.instance_id);
        fs::write(dst.join("instance.json"), instance_doc).map_err(|_| ())?;
        if let Ok(reseed) = fs::read(Path::new(&self.roots.state_root).join("reseed.json")) {
            fs::write(dst.join("reseed.json"), reseed).map_err(|_| ())?;
        }
        Ok(())
    }

    /// `collectTLSCerts` — only the certificates are extracted; the keys
    /// never leave the broker root. The persisted `tls-authority.json`
    /// carries std-base64 `ca_cert`/`leaf_cert`; the export document
    /// re-encodes them raw-URL.
    fn collect_tls_certs(&self, dst: &Path) -> Result<(), ()> {
        let raw = fs::read(Path::new(&self.roots.broker_protected_dir).join("tls-authority.json"))
            .map_err(|_| ())?;
        #[derive(Deserialize)]
        struct State {
            ca_cert: String,
            leaf_cert: String,
        }
        let state: State = serde_json::from_slice(&raw).map_err(|_| ())?;
        let ca = crate::broker::wire::b64_decode(&state.ca_cert).ok_or(())?;
        let leaf = crate::broker::wire::b64_decode(&state.leaf_cert).ok_or(())?;
        if ca.is_empty() || leaf.is_empty() {
            return Err(());
        }
        let certs = format!(
            "{{\"ca_cert_b64\":\"{}\",\"leaf_cert_b64\":\"{}\"}}\n",
            crate::broker::wire::b64_url_raw_encode(&ca),
            crate::broker::wire::b64_url_raw_encode(&leaf)
        );
        fs::write(dst.join("tls-certs.json"), certs).map_err(|_| ())
    }
}

/// `copyTree`/`copyImportTree` — copies a directory tree without
/// following symlinks; anything that is not a regular file or
/// directory aborts the copy. Shared by export staging and import
/// bootstrap/plan writes.
pub(crate) fn copy_tree(src: &Path, dst: &Path) -> Result<(), ()> {
    let mut stack = vec![src.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|_| ())? {
            let entry = entry.map_err(|_| ())?;
            let ft = entry.file_type().map_err(|_| ())?;
            if ft.is_symlink() {
                return Err(());
            }
            let rel = entry
                .path()
                .strip_prefix(src)
                .map_err(|_| ())?
                .to_path_buf();
            let target = dst.join(&rel);
            if ft.is_dir() {
                fs::create_dir_all(&target).map_err(|_| ())?;
                stack.push(entry.path());
                continue;
            }
            if !ft.is_file() {
                return Err(());
            }
            fs::copy(entry.path(), &target).map_err(|_| ())?;
        }
    }
    Ok(())
}

/// `writeExportManifest` — walks the staged `backup/` and `protected/`
/// trees, records every file's digest, and writes `manifest.json` at
/// the stage root.
fn write_export_manifest(
    payload: &Path,
    bundle_id: &str,
    instance_id: &str,
    now: OffsetDateTime,
) -> Result<domain::ExportManifest, ()> {
    let mut manifest = domain::ExportManifest {
        bundle_id: bundle_id.to_owned(),
        instance_id: instance_id.to_owned(),
        created_at: domain::format_rfc3339_nano(now),
        purpose: domain::EXPORT_PURPOSE.to_owned(),
        files: Vec::new(),
        body_count: 0,
    };
    for tree in ["backup", "protected"] {
        let mut rels: Vec<PathBuf> = Vec::new();
        let mut stack = vec![payload.join(tree)];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).map_err(|_| ())? {
                let entry = entry.map_err(|_| ())?;
                let ft = entry.file_type().map_err(|_| ())?;
                if ft.is_dir() {
                    stack.push(entry.path());
                    continue;
                }
                rels.push(
                    entry
                        .path()
                        .strip_prefix(payload)
                        .map_err(|_| ())?
                        .to_path_buf(),
                );
            }
        }
        rels.sort();
        let mut count = 0i64;
        for rel in rels {
            let full = payload.join(&rel);
            let raw = fs::read(&full).map_err(|_| ())?;
            manifest.files.push(domain::ManifestFile {
                path: rel.to_string_lossy().replace('\\', "/"),
                size: raw.len() as i64,
                sha256: portable::sha256_hex(&raw),
            });
            count += 1;
        }
        if tree == "backup" {
            manifest.body_count = count;
        }
    }
    let encoded = serde_json::to_string_pretty(&manifest).map_err(|_| ())?;
    fs::write(payload.join("manifest.json"), format!("{encoded}\n")).map_err(|_| ())?;
    Ok(manifest)
}

/// Removes the staging tree even on early returns — upstream's
/// `defer os.RemoveAll(stage)`.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Production source — `repositoryExportSource`.
// ---------------------------------------------------------------------------

/// `repositoryExportSource` — the production `exportBackupSource`: the
/// read-only backup repository opened through the same
/// descriptor + binding + instance-match discipline as every other
/// backup reader.
pub struct RepositoryExportSource {
    /// The backup repository root (`<state>/backups`).
    pub root: PathBuf,
    /// The owning instance id the repository binding must match.
    pub instance_id: String,
    /// The recovery profile the seal check runs under.
    pub profile: central_backup::backup::capacity::RecoveryProfile,
}

impl RepositoryExportSource {
    /// `repositoryExportSource.open` — descriptor, binding, instance
    /// match, read-only handle.
    fn open(&self) -> Result<crate::backup::repository::Repository, Failure> {
        if !self.root.is_absolute() {
            return Err(Failure::unavailable(
                "export_source",
                "export: repository root unavailable",
            ));
        }
        let fd = rustix::fs::open(
            &self.root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| Failure::unavailable("export_source", "export: repository unavailable"))?;
        let binding =
            crate::backup::repository::inspect_repository_descriptor(&fd).map_err(|_| {
                Failure::unavailable("export_source", "export: repository binding mismatch")
            })?;
        if !self.instance_id.is_empty() && binding.instance_id != self.instance_id {
            return Err(Failure::unavailable(
                "export_source",
                "export: repository binding mismatch",
            ));
        }
        crate::backup::repository::Repository::read_only_from_descriptor(&fd, &binding)
            .map_err(|_| Failure::unavailable("export_source", "export: repository unavailable"))
    }
}

impl ExportBackupSource for RepositoryExportSource {
    fn list_sealed_backup_ids(&self) -> Result<Vec<Uuid>, Failure> {
        self.open()?.sealed_backup_ids()
    }

    fn verify_and_stage_backup(&self, backup_id: Uuid, stage_dir: &Path) -> Result<(), Failure> {
        if backup_id.is_nil() {
            return Err(Failure::invalid(
                "export_source",
                "export: backup id is empty",
            ));
        }
        let repository = self.open()?;
        repository
            .verify_backup(backup_id, &self.profile)
            .map_err(|_| Failure::invalid("export_source", "export: backup is not sealed"))?;
        // The seal held; copy the sealed tree for archiving. The
        // repository root is helper-owned, so the walk cannot be
        // redirected by the operator; symlinks and special files are
        // refused regardless.
        let backup_dir = self.root.join("backups").join(backup_id.to_string());
        copy_tree(&backup_dir, stage_dir).map_err(|_| {
            Failure::unavailable("export_source", "export: sealed tree staging failed")
        })
    }
}

// ---------------------------------------------------------------------------
// Client — `client_linux.go`'s export half.
// ---------------------------------------------------------------------------

/// `ExportClientResult` mirrors the helper's `ExportResult`.
pub type ExportClientResult = ExportResult;

/// `ExportClientError` — only the stable exit class plus a whitelisted
/// reason token cross the boundary.
#[derive(Debug)]
pub struct ExportClientError {
    exit_code: i64,
    reason: String,
}

impl ExportClientError {
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
        new_export_client_error(exit_code, reason)
    }
}

impl std::fmt::Display for ExportClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("helper: export failed")
    }
}

impl std::error::Error for ExportClientError {}

fn retained_export_reason(reason: &str) -> String {
    match reason {
        r if r == super::delete::DENY_SAFE_ACTIVE_WIRE_REASON
            || r == domain::REASON_EXPORT_SELF_VERIFY_FAILED
            || r == domain::REASON_EXPORT_NO_BACKUP
            || r == domain::REASON_EXPORT_BACKUP_AMBIGUOUS
            || r == domain::REASON_EXPORT_BACKUP_UNSEALED
            || r == domain::REASON_EXPORT_OUT_INVALID
            || r == domain::REASON_EXPORT_IDENTITY_FAILED
            || r == domain::REASON_EXPORT_CEREMONY_REQUIRED
            || r == domain::REASON_EXPORT_AUTHORITY_DENIED =>
        {
            r.to_owned()
        }
        _ => String::new(),
    }
}

fn new_export_client_error(exit_code: i64, reason: &str) -> ExportClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    ExportClientError {
        exit_code,
        reason: retained_export_reason(reason),
    }
}

/// `ExportClient` — `NewExportClient`'s linux implementation.
pub struct ExportClient {
    socket_path: String,
}

/// `filepath.Base` — the client returns basenames only; anything with a
/// separator is a transport violation.
fn is_base_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\')
}

impl ExportClient {
    /// `NewExportClient`.
    #[must_use]
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `Export` — one bounded request/response exchange.
    pub fn export(
        &self,
        operation_id: &str,
        backup_id: &str,
        out_dir: &str,
    ) -> Result<ExportClientResult, ExportClientError> {
        if self.socket_path.is_empty() || operation_id.is_empty() || out_dir.is_empty() {
            return Err(new_export_client_error(3, ""));
        }
        let mut conn = std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(|_| new_export_client_error(3, ""))?;
        let bound = Duration::from_secs(5);
        let _ = conn.set_read_timeout(Some(bound));
        let _ = conn.set_write_timeout(Some(bound));
        #[derive(Serialize)]
        struct Payload<'a> {
            #[serde(skip_serializing_if = "str::is_empty")]
            backup_id: &'a str,
            out_dir: &'a str,
        }
        let payload = serde_json::to_string(&Payload { backup_id, out_dir })
            .ok()
            .and_then(|s| serde_json::value::RawValue::from_string(s).ok());
        write_request(
            &mut conn,
            &Request {
                operation_id: operation_id.to_owned(),
                verb: super::verb::BACKUP_EXPORT.to_owned(),
                payload,
            },
        )
        .map_err(|_| new_export_client_error(3, ""))?;
        let response = read_response(&mut conn).map_err(|_| new_export_client_error(3, ""))?;
        if response.outcome != "success" || response.exit_code != 0 {
            return Err(new_export_client_error(
                response.exit_code,
                &response.reason,
            ));
        }
        let payload = response
            .result
            .as_ref()
            .map(|r| r.get().as_bytes().to_vec())
            .unwrap_or_default();
        let result: ExportClientResult = super::backup::decode_exact_backup_read_result(&payload)
            .map_err(|_| new_export_client_error(6, ""))?;
        // The helper's echo is proven, not trusted: operation id, file
        // basenames, and non-empty identities are re-checked here.
        if result.operation_id != operation_id
            || result.bundle_id.is_empty()
            || result.backup_id.is_empty()
            || result.instance_id.is_empty()
            || result.token_id.is_empty()
            || result.public_key_hex.is_empty()
            || result.bundle_sha256.len() != 64
            || !result.bundle_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || !is_base_name(&result.bundle_file)
            || !is_base_name(&result.token_file)
            || result.completed_at.is_empty()
        {
            return Err(new_export_client_error(6, ""));
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Tests — `export_test.go` coverage: request grammar, pre-ceremony
// validation, candidate resolution, ceremony outcomes, and the full
// produce-then-self-verify path.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_INSTANCE: &str = "019b0000-0000-7000-8000-000000000001";

    fn tmp(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("central-export-test-{tag}-{}", std::process::id()));
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

    /// `recordingPAM` — a granting ceremony that counts invocations so
    /// pre-ceremony refusals are proven, not assumed.
    struct CountingPam {
        calls: AtomicUsize,
        grant: bool,
    }

    impl ExportPamConfirmer for CountingPam {
        fn verify_and_consume(&self, _t: &str) -> bool {
            true
        }
        fn confirm_backup_export(
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

    /// `fixtureSource` — lists a canned sealed set and stages a dump +
    /// one body on verification.
    struct StubSource {
        ids: Vec<Uuid>,
        stage_ok: bool,
    }

    impl ExportBackupSource for StubSource {
        fn list_sealed_backup_ids(&self) -> Result<Vec<Uuid>, Failure> {
            Ok(self.ids.clone())
        }
        fn verify_and_stage_backup(&self, _id: Uuid, stage_dir: &Path) -> Result<(), Failure> {
            if !self.stage_ok {
                return Err(Failure::denied("seal", "unsealed"));
            }
            fs::create_dir_all(stage_dir.join("wal"))
                .and_then(|()| fs::write(stage_dir.join("central.dump"), b"pgdump"))
                .and_then(|()| fs::write(stage_dir.join("wal").join("0001.seg"), b"x"))
                .map_err(|e| Failure::unavailable("stage", e.to_string()))
        }
    }

    /// The resolved-composition fixture: a state root with `config.json`,
    /// a broker protected dir with `tls-authority.json`, a staging
    /// parent, and the operator's out dir.
    fn fixture(tag: &str) -> (PathBuf, ExportRoots, PathBuf) {
        let base = tmp(tag);
        let state = base.join("state");
        fs::create_dir_all(&state).expect("state");
        fs::write(state.join("config.json"), b"{\"instance_id\":\"x\"}")
            .expect("config");
        let broker = base.join("broker").join("protected");
        fs::create_dir_all(&broker).expect("broker");
        let tls = format!(
            "{{\"ca_cert\":\"{}\",\"leaf_cert\":\"{}\"}}",
            crate::broker::wire::b64_encode(b"ca-der"),
            crate::broker::wire::b64_encode(b"leaf-der")
        );
        fs::write(broker.join("tls-authority.json"), tls).expect("tls");
        let staging = base.join("staging");
        fs::create_dir_all(&staging).expect("staging");
        let out = base.join("out");
        fs::create_dir_all(&out).expect("out");
        let roots = ExportRoots {
            instance_id: TEST_INSTANCE.to_owned(),
            state_root: state.to_string_lossy().into_owned(),
            broker_protected_dir: broker.to_string_lossy().into_owned(),
            instances_parent_uid: 0,
            instances_parent_gid: 0,
            instance_uid: rustix::process::geteuid().as_raw(),
            instance_gid: rustix::process::getegid().as_raw(),
            staging_parent: staging.to_string_lossy().into_owned(),
        };
        (base, roots, out)
    }

    fn request(out: &Path, backup_id: &str) -> ExportRequest {
        ExportRequest {
            operation_id: Uuid::now_v7().to_string(),
            backup_id: backup_id.to_owned(),
            out_dir: out.to_string_lossy().into_owned(),
        }
    }

    fn decode_result(resp: &Response) -> ExportResult {
        serde_json::from_str(
            resp.result
                .as_ref()
                .expect("no result")
                .get(),
        )
        .expect("decode")
    }

    /// `TestExportRejectsInvalidOutDirBeforeCeremony` — a relative or
    /// missing out dir denies with `EXPORT_OUT_INVALID` and never
    /// reaches the ceremony.
    #[test]
    fn export_rejects_bad_out_dir_before_ceremony() {
        let (_base, roots, _out) = fixture("badout");
        let pam = CountingPam {
            calls: AtomicUsize::new(0),
            grant: true,
        };
        let handler = ExportHandlerImpl::new(
            Some(Box::new(pam)),
            scope(),
            roots,
            Some(Box::new(StubSource {
                ids: vec![Uuid::now_v7()],
                stage_ok: true,
            })),
        );
        for bad in [
            "relative/dir",
            "/definitely/missing-export-out",
            "/tmp/../bad",
        ] {
            let resp = handler.export(
                Instant::now() + Duration::from_secs(60),
                ExportRequest {
                    out_dir: bad.to_owned(),
                    ..request(Path::new("/tmp"), "")
                },
                &peer(),
            );
            assert_eq!(resp.outcome, "denied", "{bad}");
            assert_eq!(resp.reason, domain::REASON_EXPORT_OUT_INVALID, "{bad}");
        }
    }

    /// `TestExportRequiresCeremonySeam` — a handler composed without a
    /// confirmer fails closed with `EXPORT_CEREMONY_REQUIRED`.
    #[test]
    fn export_requires_configured_ceremony() {
        let (_base, roots, out) = fixture("nopam");
        let handler = ExportHandlerImpl::new(
            None,
            scope(),
            roots,
            Some(Box::new(StubSource {
                ids: vec![Uuid::now_v7()],
                stage_ok: true,
            })),
        );
        let resp = handler.export(
            Instant::now() + Duration::from_secs(60),
            request(&out, ""),
            &peer(),
        );
        assert_eq!(resp.outcome, "denied");
        assert_eq!(resp.reason, domain::REASON_EXPORT_CEREMONY_REQUIRED);
    }

    /// `TestExportDeniedCeremony` — a refused ceremony maps to
    /// `AUTHORITY_DENIED` without touching the output dir.
    #[test]
    fn export_denied_ceremony() {
        let (_base, roots, out) = fixture("denypam");
        let pam = CountingPam {
            calls: AtomicUsize::new(0),
            grant: false,
        };
        let handler = ExportHandlerImpl::new(
            Some(Box::new(pam)),
            scope(),
            roots,
            Some(Box::new(StubSource {
                ids: vec![Uuid::now_v7()],
                stage_ok: true,
            })),
        );
        let resp = handler.export(
            Instant::now() + Duration::from_secs(60),
            request(&out, ""),
            &peer(),
        );
        assert_eq!(resp.outcome, "denied");
        assert_eq!(resp.reason, domain::REASON_EXPORT_AUTHORITY_DENIED);
        assert!(
            fs::read_dir(&out)
                .map(|mut d| d.next().is_none())
                .unwrap_or(false)
        );
    }

    /// `TestExportBackupResolution` — zero candidates, two candidates,
    /// and an explicit unsealed id each carry their own reason.
    #[test]
    fn export_candidate_resolution() {
        let (_base, roots, out) = fixture("resolve");
        for (ids, explicit, want) in [
            (vec![], "", domain::REASON_EXPORT_NO_BACKUP),
            (
                vec![Uuid::now_v7(), Uuid::now_v7()],
                "",
                domain::REASON_EXPORT_BACKUP_AMBIGUOUS,
            ),
            (
                vec![Uuid::now_v7()],
                Uuid::now_v7().to_string().leak(),
                domain::REASON_EXPORT_BACKUP_UNSEALED,
            ),
        ] {
            let handler = ExportHandlerImpl::new(
                Some(Box::new(CountingPam {
                    calls: AtomicUsize::new(0),
                    grant: true,
                })),
                scope(),
                roots.clone(),
                Some(Box::new(StubSource {
                    ids,
                    stage_ok: true,
                })),
            );
            let resp = handler.export(
                Instant::now() + Duration::from_secs(60),
                request(&out, explicit),
                &peer(),
            );
            assert_eq!(resp.outcome, "denied");
            assert_eq!(resp.reason, want, "{want}");
        }
    }

    /// `TestExportRoundTrip` — the full path produces a self-verified
    /// bundle, a token bound to its digest, and the identity marker
    /// under the state root; the emitted artifacts are then proven with
    /// the domain verifier, not trusted.
    #[test]
    fn export_round_trip_produces_verifiable_bundle() {
        let (base, roots, out) = fixture("roundtrip");
        let backup = Uuid::now_v7();
        let handler = ExportHandlerImpl::new(
            Some(Box::new(CountingPam {
                calls: AtomicUsize::new(0),
                grant: true,
            })),
            scope(),
            roots,
            Some(Box::new(StubSource {
                ids: vec![backup],
                stage_ok: true,
            })),
        );
        let req = request(&out, &backup.to_string());
        let op = req.operation_id.clone();
        let resp = handler.export(Instant::now() + Duration::from_secs(300), req, &peer());
        assert_eq!(resp.outcome, "success");
        assert_eq!(resp.exit_code, 0);
        let result = decode_result(&resp);
        assert_eq!(result.operation_id, op);
        assert_eq!(result.backup_id, backup.to_string());
        assert_eq!(result.instance_id, TEST_INSTANCE);
        assert!(result.identity_created);
        assert_eq!(result.public_key_hex.len(), 64);
        assert_eq!(result.body_count, 2);
        // Artifacts: O_EXCL-written bundle + token in the operator dir.
        let bundle_path = out.join(&result.bundle_file);
        let token_path = out.join(&result.token_file);
        assert_eq!(
            portable::sha256_file(&bundle_path).ok().as_deref(),
            Some(result.bundle_sha256.as_str())
        );
        assert_eq!(
            fs::metadata(&bundle_path)
                .map(|m| m.len() as i64)
                .unwrap_or(-1),
            result.bundle_bytes
        );
        let token: domain::Bx1Token =
            serde_json::from_slice(&fs::read(&token_path).expect("token"))
                .expect("token json");
        domain::verify_bx1_token(
            &token,
            &result.public_key_hex,
            &result.bundle_sha256,
            OffsetDateTime::now_utc(),
        )
        .expect("verify");
        // The bundle's own nonce re-derives the same key and the stream
        // authenticates end to end — the importer's trust path.
        let nonce = domain::b64_url_raw_decode(&token.nonce_b64).expect("nonce");
        let key = domain::derive_bundle_key(&nonce).expect("key");
        let mut plain = Vec::new();
        portable::decrypt_stream(
            fs::File::open(&bundle_path).expect("open"),
            &mut plain,
            &key,
        )
        .expect("decrypt");
        assert!(!plain.is_empty());
        // The minted identity persists under the state root, not the
        // operator dir.
        assert!(base.join("state").join("export-identity.json").exists());
    }
}
