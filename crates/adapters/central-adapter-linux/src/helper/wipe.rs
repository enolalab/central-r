//! `internal/adapter/authority/helper/wipe.go` + `client_linux.go`'s
//! wipe half — the D01 helper verb: signed-denial pre-check, the wipe
//! ceremony, checkpoint verification, AppArmor handling, protected-state
//! deletion of the instance state root and its broker root, and reseed
//! with a fresh identity. The filesystem seams
//! (`internal/destructive/{wipe,reseed}.go`) live here too — the helper
//! is the audited OS boundary, `central-infra::destructive` stays pure.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use central_foundation::failure::Failure;
use central_foundation::identity::InstanceId;
use central_infra::destructive::{
    self as domain, AppArmorState, WipeDomainError, WipeIntent, WipeResultRecord, WipeTarget,
};

use super::PeerIdentity;
use super::grant::CeremonyScope;
use super::protocol::{Request, Response, read_response, strict_decode, write_request};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// `WipeRequest` — the typed wipe payload. `target_path` is the
/// operator's descriptor-bound selection (the exact canonical state-root
/// path); the handler refuses anything that does not resolve to its own
/// installed instance root. `checkpoint_backup_id` names the sealed C01
/// backup the CLI created for this wipe.
#[derive(Debug, Clone)]
pub struct WipeRequest {
    /// The ceremony-bound operation (envelope field, not payload).
    pub operation_id: String,
    /// The state-root path to destroy.
    pub target_path: String,
    /// The sealed checkpoint backup id.
    pub checkpoint_backup_id: String,
}

/// `WipeResult` — the bounded wipe outcome: identities and state only,
/// never a path, descriptor, credential, or diagnostic text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeResult {
    /// The ceremony-bound operation.
    pub operation_id: String,
    /// The wiped instance.
    pub wiped_instance_id: String,
    /// The reseeded instance identity.
    pub new_instance_id: String,
    /// The sealed checkpoint backup id.
    pub checkpoint_backup_id: String,
    /// What the AppArmor seam observed/did.
    pub apparmor: String,
    /// Whether this run completed a crashed predecessor.
    pub resumed_after_crash: bool,
    /// RFC 3339 completion timestamp.
    pub completed_at: String,
}

/// `ParseWipeRequest` — rejects unknown fields so a flag or path the
/// handler does not understand cannot silently become authority.
pub fn parse_wipe_request(req: &Request) -> Result<WipeRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing wipe operation".to_owned());
    }
    let trimmed = trim_ascii(req.payload_bytes());
    if trimmed.is_empty() {
        return Err("helper: wipe requires a target_path payload".to_owned());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        target_path: String,
        checkpoint_backup_id: String,
    }
    let payload: Payload =
        strict_decode(trimmed).map_err(|_| "helper: invalid wipe payload".to_owned())?;
    if payload.target_path.is_empty() || payload.checkpoint_backup_id.is_empty() {
        return Err("helper: wipe requires target_path and checkpoint_backup_id".to_owned());
    }
    Ok(WipeRequest {
        operation_id: req.operation_id.clone(),
        target_path: payload.target_path,
        checkpoint_backup_id: payload.checkpoint_backup_id,
    })
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

fn wipe_response(
    operation_id: &str,
    outcome: &str,
    code: i64,
    reason: &str,
    result: Option<&WipeResult>,
) -> Response {
    let mut resp = Response::new(operation_id, outcome, code, reason);
    if let Some(r) = result {
        resp = resp.with_result(r);
    }
    resp
}

// ---------------------------------------------------------------------------
// Seams — upstream's per-verb interfaces, kept separate for the same
// reason: a confirmer that can only authorize a restore must not be
// usable to authorize destroying the whole instance.
// ---------------------------------------------------------------------------

/// `wipePAMConfirmer` — the fourth destructive ceremony. The handler
/// refuses when the installed confirmer cannot do this (`None`).
pub trait WipePamConfirmer: Send + Sync {
    /// `VerifyAndConsume` — minted tokens are one-use.
    fn verify_and_consume(&self, token: &str) -> bool;
    /// `ConfirmWipe` — `Some` where the confirmer supports this
    /// exact ceremony.
    fn confirm_wipe(
        &self,
        _peer: PeerIdentity,
        _deadline: Option<Instant>,
        _scope: &CeremonyScope,
        _operation_id: &str,
    ) -> Option<Result<String, Failure>> {
        None
    }
}

/// `wipeAdvisoryEvaluator` — the B01 seam. Wipe proceeds only on a
/// `current` result — the same strictness `Admission::new` enforces —
/// so a denied, stale, expired, or unevaluable advisory refuses the
/// wipe before any ceremony.
pub trait WipeAdvisoryEvaluator: Send + Sync {
    /// `Evaluate`.
    fn evaluate(
        &self,
    ) -> Result<
        (
            super::prepare::AdvisoryResult,
            super::prepare::AdvisoryAdmission,
        ),
        Failure,
    >;
}

/// `wipeCheckpointVerifier` — confirms the C01 checkpoint backup the
/// CLI created is sealed. Production adapts
/// [`super::backup::BackupReader::verify_backup`]; the verifier sees
/// only the backup id.
pub trait WipeCheckpointVerifier: Send + Sync {
    /// `VerifySealed`.
    fn verify_sealed(
        &self,
        deadline: Instant,
        backup_id: &str,
        peer: &PeerIdentity,
    ) -> Result<(), Failure>;
}

// `unavailableLifecycleEvaluator` — upstream's deny-only stub moved to
// the shared `daemon::HelperAdvisoryEvaluator` when B01's evaluator was
// wired into the composition (upstream newHelperAdvisoryEvaluator): one
// evaluator, one fail-closed arm — never a second place for a deny-only
// default to be swapped for something more permissive.

/// `wipeCheckpointAdapter` — answers the wipe handler's one checkpoint
/// question through the backup-read surface: `verify_backup` on the
/// sealed checkpoint re-verifies its seal, which is the dossier's
/// "created and verified".
pub struct BackupReaderCheckpointVerifier {
    /// The server's backup-read seam.
    pub read: Box<dyn super::backup::BackupReader>,
}

impl WipeCheckpointVerifier for BackupReaderCheckpointVerifier {
    fn verify_sealed(
        &self,
        deadline: Instant,
        backup_id: &str,
        peer: &PeerIdentity,
    ) -> Result<(), Failure> {
        let resp = self.read.verify_backup(
            deadline,
            super::backup::BackupVerifyRequest {
                backup_id: backup_id.to_owned(),
            },
            peer,
        );
        if resp.outcome != "success" || resp.exit_code != 0 {
            return Err(Failure::unavailable(
                "wipe_checkpoint",
                "wipe: checkpoint backup is not sealed",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Roots + handler
// ---------------------------------------------------------------------------

/// `WipeRoots` pins the three filesystem hierarchies a wipe touches.
/// All paths are absolute and clean in production; tests substitute a
/// fixture tree.
#[derive(Debug, Clone)]
pub struct WipeRoots {
    /// Holds `<instance-id>/` state roots.
    pub instances_root: String,
    /// Holds `<instance-id>/protected` broker roots.
    pub protected_parent: String,
    /// Holds `<instance-id>/` ephemeral runtime roots; presence of the
    /// instance's dir is the live-instance proof that refuses a wipe.
    pub runtime_base: String,
    /// Owner/group of the two parents (root in production).
    pub parent_uid: u32,
    /// See `parent_uid`.
    pub parent_gid: u32,
    /// Owner/group of instance state roots (central-runtime).
    pub instance_uid: u32,
    /// See `instance_uid`.
    pub instance_gid: u32,
}

/// `AppArmorDeps` — the confinement seams. Production values are the
/// fixed paths; tests substitute a fixture tree and stubbed runners.
#[derive(Clone)]
pub struct AppArmorDeps {
    /// Read for the helper's own confinement. Production:
    /// `/proc/self/attr/current` ("unconfined" or "profile (enforce)").
    pub attr_current_path: String,
    /// The sandbox launcher's profile file. Production:
    /// `/etc/apparmor.d/central-sandbox-launcher`.
    pub profile_path: String,
    /// `exec.LookPath`.
    pub look_path: fn(&str) -> Result<PathBuf, Failure>,
    /// `exec.CommandContext(...).Run()`.
    pub run: fn(&str, &[&str]) -> Result<(), Failure>,
}

/// `ProductionAppArmorDeps` — the production seams.
#[must_use]
pub fn production_app_armor_deps() -> AppArmorDeps {
    AppArmorDeps {
        attr_current_path: domain::APPARMOR_ATTR_CURRENT.to_owned(),
        profile_path: domain::APPARMOR_PROFILE.to_owned(),
        look_path,
        run: |name, args| {
            std::process::Command::new(name)
                .args(args)
                .status()
                .map_err(|e| Failure::unavailable("apparmor_run", e.to_string()))
                .and_then(|s| {
                    if s.success() {
                        Ok(())
                    } else {
                        Err(Failure::unavailable("apparmor_run", "non-zero exit"))
                    }
                })
        },
    }
}

fn look_path(name: &str) -> Result<PathBuf, Failure> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return if p.is_file() {
            Ok(p)
        } else {
            Err(Failure::unavailable("look_path", "not found"))
        };
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return Err(Failure::unavailable("look_path", "no PATH"));
    };
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(Failure::unavailable("look_path", "not found"))
}

/// `WipeHandlerImpl` — performs D01.
pub struct WipeHandlerImpl {
    pam: Option<Box<dyn WipePamConfirmer>>,
    advisory: Option<Box<dyn WipeAdvisoryEvaluator>>,
    checkpoint: Option<Box<dyn WipeCheckpointVerifier>>,
    scope: CeremonyScope,
    roots: WipeRoots,
    apparmor: AppArmorDeps,
    new_id: fn() -> InstanceId,
    now: fn() -> OffsetDateTime,
}

/// `WipeHandler` — the `Server::wipe` field type.
pub trait WipeHandler: Send + Sync {
    /// `Wipe`.
    fn wipe(&self, deadline: Instant, request: WipeRequest, peer: &PeerIdentity) -> Response;
}

impl WipeHandlerImpl {
    /// `NewWipeHandler`. Any `None` seam refuses every request rather
    /// than running degraded.
    #[must_use]
    pub fn new(
        pam: Option<Box<dyn WipePamConfirmer>>,
        advisory: Option<Box<dyn WipeAdvisoryEvaluator>>,
        checkpoint: Option<Box<dyn WipeCheckpointVerifier>>,
        scope: CeremonyScope,
        roots: WipeRoots,
        apparmor: AppArmorDeps,
    ) -> Self {
        Self {
            pam,
            advisory,
            checkpoint,
            scope,
            roots,
            apparmor,
            new_id: InstanceId::new,
            now: OffsetDateTime::now_utc,
        }
    }

    /// `resumeOrRefuse` — a wipe whose target resolves to nothing.
    /// A crash intent naming exactly the requested path completes the
    /// reseed half under the ceremony this invocation already performed;
    /// anything else is refused rather than guessed.
    fn resume_or_refuse(&self, request: &WipeRequest) -> Response {
        let intent = match find_stale_intent(&self.roots.instances_root) {
            Ok(Some(intent)) => intent,
            Ok(None) => {
                return wipe_response(
                    &request.operation_id,
                    "denied",
                    2,
                    domain::REASON_WIPE_INVALID_REQUEST,
                    None,
                );
            }
            Err(_) => {
                return wipe_response(
                    &request.operation_id,
                    "denied",
                    2,
                    domain::REASON_WIPE_INVALID_REQUEST,
                    None,
                );
            }
        };
        if !domain::wipe_resume_request_matches(
            &request.target_path,
            &self.roots.instances_root,
            &intent,
        ) || intent.checkpoint_backup_id != request.checkpoint_backup_id
        {
            return wipe_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_WIPE_INVALID_REQUEST,
                None,
            );
        }
        // Re-verify confinement on the resume path: it is idempotent
        // (a removed profile stays removed) and a confined resume must
        // not reseed blindly.
        let apparmor = match ensure_unconfined(&self.apparmor) {
            Ok(state) => state,
            Err(_) => {
                return wipe_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_WIPE_APPARMOR_REFUSED,
                    None,
                );
            }
        };
        let mut resumed = intent;
        resumed.operation_id = request.operation_id.clone();
        self.finish_reseed(&resumed, apparmor, true)
    }

    /// `finishReseed` — rebuilds both skeletons under a fresh identity,
    /// verifies the result, and writes the terminal audit record.
    fn finish_reseed(
        &self,
        intent: &WipeIntent,
        apparmor: AppArmorState,
        resumed: bool,
    ) -> Response {
        let new_id = (self.new_id)();
        let new_root = format!("{}/{}", self.roots.instances_root, new_id);
        let reseed_failed = || {
            wipe_response(
                &intent.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_RESEED_FAILED,
                None,
            )
        };
        let Ok(rewritten) =
            domain::rewrite_config_for_instance(intent.config_json.as_bytes(), new_id, &new_root)
        else {
            return reseed_failed();
        };
        if reseed_instance(
            &domain::ReseedInput {
                instances_root: self.roots.instances_root.clone(),
                protected_parent: self.roots.protected_parent.clone(),
                new_instance_id: new_id.to_string(),
                config_bytes: rewritten,
                instance_uid: self.roots.instance_uid,
                instance_gid: self.roots.instance_gid,
                broker_uid: self.roots.parent_uid,
                broker_gid: self.roots.parent_gid,
            },
            self.now,
            &intent.instance_id,
            &intent.checkpoint_backup_id,
        )
        .is_err()
        {
            return reseed_failed();
        }
        if verify_reseed_fresh(
            &new_root,
            &format!("{}/{new_id}/protected", self.roots.protected_parent),
            &new_id.to_string(),
        )
        .is_err()
        {
            return reseed_failed();
        }
        // Bind the fresh instance's empty backup repository before the
        // wipe completes: every later launch that opens the repository
        // finds a bound root instead of an unbound directory.
        if bind_fresh_backup_repository(&format!("{new_root}/backups"), &new_id.to_string())
            .is_err()
        {
            return reseed_failed();
        }
        let completed = rfc3339_now(self.now);
        if complete_wipe(
            &self.roots.instances_root,
            &WipeResultRecord {
                operation_id: intent.operation_id.clone(),
                instance_id: intent.instance_id.clone(),
                new_instance_id: new_id.to_string(),
                checkpoint_backup_id: intent.checkpoint_backup_id.clone(),
                apparmor,
                resumed_after_crash: resumed,
                completed_at: completed.clone(),
                reason: "ok".to_owned(),
            },
            self.roots.parent_uid,
            self.roots.parent_gid,
        )
        .is_err()
        {
            return reseed_failed();
        }
        wipe_response(
            &intent.operation_id,
            "success",
            0,
            "ok",
            Some(&WipeResult {
                operation_id: intent.operation_id.clone(),
                wiped_instance_id: intent.instance_id.clone(),
                new_instance_id: new_id.to_string(),
                checkpoint_backup_id: intent.checkpoint_backup_id.clone(),
                apparmor: apparmor.as_str().to_owned(),
                resumed_after_crash: resumed,
                completed_at: completed,
            }),
        )
    }
}

impl WipeHandler for WipeHandlerImpl {
    /// `Wipe` — the dossier's order: advisory denial before ceremony,
    /// ceremony before checkpoint verification, verification before
    /// destruction, destruction before reseed. Every destructive step
    /// runs only after the ceremony minted and spent its token.
    fn wipe(&self, deadline: Instant, request: WipeRequest, peer: &PeerIdentity) -> Response {
        let op_ok =
            Uuid::parse_str(&request.operation_id).is_ok_and(|u| !u.is_nil()) && peer.pid > 0;
        let seams_ok = self.pam.is_some()
            && self.advisory.is_some()
            && self.checkpoint.is_some()
            && !self.scope.instance_id.is_empty()
            && !self.scope.target_id.is_empty()
            && !self.roots.instances_root.is_empty()
            && !self.roots.protected_parent.is_empty()
            && !self.roots.runtime_base.is_empty();
        if !op_ok || !seams_ok {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_CEREMONY_REQUIRED,
                None,
            );
        }
        if Uuid::parse_str(&request.checkpoint_backup_id).is_err() {
            return wipe_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_WIPE_INVALID_REQUEST,
                None,
            );
        }
        // Signed denial first: a non-current advisory refuses the wipe
        // even with a valid ceremony, so no prompt is ever shown for a
        // doomed wipe.
        let advisory = self.advisory.as_ref().map(|a| a.as_ref());
        let Some(evaluator) = advisory else {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_DENIED_SIGNED,
                None,
            );
        };
        let Ok((verdict, _admission)) = evaluator.evaluate() else {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_DENIED_SIGNED,
                None,
            );
        };
        if verdict.state != super::prepare::ADVISORY_STATE_CURRENT {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_DENIED_SIGNED,
                None,
            );
        }
        // Target shape before ceremony: a malformed selection fails
        // before authorization.
        if !domain::valid_wipe_target_syntax(&request.target_path, &self.roots.instances_root) {
            return wipe_response(
                &request.operation_id,
                "denied",
                2,
                domain::REASON_WIPE_TARGET_INVALID,
                None,
            );
        }
        let Some(pam) = self.pam.as_ref() else {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_CEREMONY_REQUIRED,
                None,
            );
        };
        // Upstream hands the ceremony the whole verb ctx — the
        // two-minute "ceremony share" is budget accounting inside
        // `wipeDeadline`, not an enforced sub-deadline (the restore
        // apply path's `confirmRestoreCeremony` is the only one that
        // binds the ceremony to its own share).
        let Some(confirmation) =
            pam.confirm_wipe(*peer, Some(deadline), &self.scope, &request.operation_id)
        else {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_CEREMONY_REQUIRED,
                None,
            );
        };
        let Ok(token) = confirmation else {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_AUTHORITY_DENIED,
                None,
            );
        };
        if !pam.verify_and_consume(&token) {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_AUTHORITY_DENIED,
                None,
            );
        }
        let checkpoint = self.checkpoint.as_ref().map(|c| c.as_ref());
        let Some(verifier) = checkpoint else {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_CHECKPOINT_FAILED,
                None,
            );
        };
        if verifier
            .verify_sealed(deadline, &request.checkpoint_backup_id, peer)
            .is_err()
        {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_CHECKPOINT_FAILED,
                None,
            );
        }
        let target = match resolve_wipe_target(
            &request.target_path,
            &self.roots.instances_root,
            self.roots.parent_uid,
            self.roots.parent_gid,
            self.roots.instance_uid,
            self.roots.instance_gid,
        ) {
            Ok(target) => target,
            Err(_) => return self.resume_or_refuse(&request),
        };
        if refuse_if_live(&format!(
            "{}/{}",
            self.roots.runtime_base, target.instance_id
        ))
        .is_err()
        {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_TARGET_LIVE,
                None,
            );
        }
        let apparmor = match ensure_unconfined(&self.apparmor) {
            Ok(state) => state,
            Err(_) => {
                return wipe_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_WIPE_APPARMOR_REFUSED,
                    None,
                );
            }
        };
        let Ok(config_bytes) = read_wipe_source_config(&target.state_root) else {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_RESEED_FAILED,
                None,
            );
        };
        let intent = WipeIntent {
            operation_id: request.operation_id.clone(),
            instance_id: target.instance_id.clone(),
            checkpoint_backup_id: request.checkpoint_backup_id.clone(),
            state_root: target.state_root.clone(),
            broker_instance_dir: format!("{}/{}", self.roots.protected_parent, target.instance_id),
            started_at: rfc3339_now(self.now),
            config_json: String::from_utf8_lossy(&config_bytes).into_owned(),
        };
        if write_wipe_intent(
            &self.roots.instances_root,
            &intent,
            self.roots.parent_uid,
            self.roots.parent_gid,
        )
        .is_err()
        {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_RESEED_FAILED,
                None,
            );
        }
        if remove_tree(&self.roots.instances_root, &target.instance_id).is_err() {
            return wipe_response(
                &request.operation_id,
                "denied",
                7,
                domain::REASON_WIPE_RESEED_FAILED,
                None,
            );
        }
        // The broker root may already be gone (a crash between the two
        // removals, or an instance that never booted its broker);
        // absence is the desired end state either way.
        let broker_dir = format!("{}/{}", self.roots.protected_parent, target.instance_id);
        match std::fs::symlink_metadata(&broker_dir) {
            Ok(_) => {
                if remove_tree(&self.roots.protected_parent, &target.instance_id).is_err() {
                    return wipe_response(
                        &request.operation_id,
                        "denied",
                        7,
                        domain::REASON_WIPE_RESEED_FAILED,
                        None,
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return wipe_response(
                    &request.operation_id,
                    "denied",
                    7,
                    domain::REASON_WIPE_RESEED_FAILED,
                    None,
                );
            }
        }
        self.finish_reseed(&intent, apparmor, false)
    }
}

// ---------------------------------------------------------------------------
// Filesystem seams — `internal/destructive/{wipe,reseed}.go` ports.
// ---------------------------------------------------------------------------

fn rfc3339_now(now: fn() -> OffsetDateTime) -> String {
    now().format(&Rfc3339).unwrap_or_default()
}

fn invalid(detail: &str) -> WipeDomainError {
    WipeDomainError::TargetInvalid(detail.to_owned())
}

fn reseed_err(detail: &str) -> WipeDomainError {
    WipeDomainError::Reseed(detail.to_owned())
}

/// `ResolveWipeTarget` — validates the operator's `--target` selection.
/// The path must canonicalize to exactly `instancesRoot/<instance-uuid>`:
/// the operator names the target and the helper refuses anything that is
/// not its own installed instance root. Parent must be a 0700 directory
/// owned by `parent_uid:parent_gid`; the target a directory owned by
/// `instance_uid:instance_gid` (checked via fd, never a fresh path walk).
pub fn resolve_wipe_target(
    operator_path: &str,
    instances_root: &str,
    parent_uid: u32,
    parent_gid: u32,
    instance_uid: u32,
    instance_gid: u32,
) -> Result<WipeTarget, WipeDomainError> {
    if !Path::new(instances_root).is_absolute() || !clean_abs(instances_root) {
        return Err(invalid("instances root"));
    }
    let abs = Path::new(operator_path);
    let canonical = std::fs::canonicalize(abs).map_err(|e| invalid(&e.to_string()))?;
    let parent = canonical
        .parent()
        .ok_or_else(|| invalid("not under the instances root"))?;
    if parent != Path::new(instances_root) {
        return Err(invalid("not under the instances root"));
    }
    let id = canonical
        .file_name()
        .and_then(|b| b.to_str())
        .ok_or_else(|| invalid("not an instance id"))?;
    let parsed = InstanceId::parse(id).map_err(|_| invalid("not an instance id"))?;
    if parsed.to_string() != id {
        return Err(invalid("not an instance id"));
    }
    let parent_fd = rustix::fs::openat(
        rustix::fs::CWD,
        instances_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| invalid("instances root unavailable"))?;
    let parent_stat = rustix::fs::fstat(&parent_fd).map_err(|_| invalid("instances root"))?;
    if rustix::fs::FileType::from_raw_mode(parent_stat.st_mode as _) != FileType::Directory
        || parent_stat.st_uid != parent_uid
        || parent_stat.st_gid != parent_gid
        || parent_stat.st_mode & 0o7777 != 0o700
    {
        return Err(invalid("instances root ownership"));
    }
    let target_fd = rustix::fs::openat(
        &parent_fd,
        id,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| invalid("target unavailable"))?;
    let target_stat = rustix::fs::fstat(&target_fd).map_err(|_| invalid("target"))?;
    if rustix::fs::FileType::from_raw_mode(target_stat.st_mode as _) != FileType::Directory
        || target_stat.st_uid != instance_uid
        || target_stat.st_gid != instance_gid
        || target_stat.st_mode & 0o7777 != 0o700
    {
        return Err(invalid("target ownership"));
    }
    Ok(WipeTarget {
        instance_id: id.to_owned(),
        state_root: canonical.to_string_lossy().into_owned(),
    })
}

/// `filepath.Clean(path) == path` for an absolute path.
fn clean_abs(path: &str) -> bool {
    domain::valid_wipe_target_syntax(path, "")
        || (path.starts_with('/')
            && !path.contains("//")
            && !path.contains("/.")
            && !path.ends_with('/'))
}

/// `RefuseIfLive` — refuses the wipe when the instance's ephemeral
/// runtime root exists: deleting protected state under a live broker or
/// serve process corrupts it. The operator runs `local down` first; an
/// absent runtime root is the down proof.
pub fn refuse_if_live(runtime_root: &str) -> Result<(), WipeDomainError> {
    match std::fs::symlink_metadata(runtime_root) {
        Ok(_) => Err(WipeDomainError::TargetLive(String::new())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(WipeDomainError::TargetLive(e.to_string())),
    }
}

/// `RemoveTree` — deletes exactly `instancesRoot/<uuid>` and verifies
/// it is gone. The prefix and UUID checks make an arbitrary-path delete
/// inexpressible.
pub fn remove_tree(instances_root: &str, instance_id: &str) -> Result<(), WipeDomainError> {
    let parsed = InstanceId::parse(instance_id).map_err(|_| invalid("not an instance id"))?;
    if parsed.to_string() != instance_id {
        return Err(invalid("not an instance id"));
    }
    if !Path::new(instances_root).is_absolute() || !clean_abs(instances_root) {
        return Err(invalid("instances root"));
    }
    let target = format!("{instances_root}/{instance_id}");
    std::fs::remove_dir_all(&target).map_err(|e| reseed_err(&e.to_string()))?;
    match std::fs::symlink_metadata(&target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(reseed_err("target survives removal")),
    }
}

/// `readWipeSourceConfig` — loads the operator config that reseed will
/// rebind. Runs before the intent is written: an unreadable config
/// refuses the wipe while everything is still intact.
fn read_wipe_source_config(state_root: &str) -> Result<Vec<u8>, WipeDomainError> {
    let raw = std::fs::read(format!("{state_root}/config.json"))
        .map_err(|_| reseed_err("source config unavailable"))?;
    if raw.is_empty() {
        return Err(reseed_err("source config unavailable"));
    }
    Ok(raw)
}

/// `readAttrCurrent` — "unconfined" or "<profile> (enforce)"; compare
/// the first field.
fn read_attr_current(path: &str) -> Result<String, WipeDomainError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| WipeDomainError::AppArmorRefused(e.to_string()))?;
    raw.split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| WipeDomainError::AppArmorRefused("empty attr/current".to_owned()))
}

/// `EnsureUnconfined` — verifies the launcher is not confined, removing
/// a present profile first. Absence of `apparmor_parser` fails closed
/// only when there is confinement work to do: an unconfined helper with
/// no profile file needs no tooling.
pub fn ensure_unconfined(deps: &AppArmorDeps) -> Result<AppArmorState, WipeDomainError> {
    let refused = |d: &str| WipeDomainError::AppArmorRefused(d.to_owned());
    let current = read_attr_current(&deps.attr_current_path)?;
    let profile_exists = std::fs::metadata(&deps.profile_path).is_ok();
    if current == "unconfined" && !profile_exists {
        return Ok(AppArmorState::NotConfined);
    }
    (deps.look_path)("apparmor_parser").map_err(|_| refused("apparmor_parser unavailable"))?;
    if profile_exists {
        (deps.run)("apparmor_parser", &["-R", &deps.profile_path])
            .map_err(|_| refused("deactivate"))?;
        std::fs::remove_file(&deps.profile_path).map_err(|_| refused("remove profile"))?;
    }
    // The parser removal above targets the installed profile; a
    // confined helper whose own label did not clear is refused, not
    // assumed fixed.
    let current = read_attr_current(&deps.attr_current_path)?;
    if current != "unconfined" {
        return Err(refused("still confined"));
    }
    Ok(AppArmorState::ProfileRemoved)
}

fn mkdir_owned(path: &str, uid: u32, gid: u32) -> Result<(), WipeDomainError> {
    std::fs::create_dir(path).map_err(|e| reseed_err(&e.to_string()))?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .map_err(|e| reseed_err(&e.to_string()))?;
    rustix::fs::chown(
        path,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    )
    .map_err(|e| reseed_err(&e.raw_os_error().to_string()))
}

fn write_owned(path: &str, data: &[u8], uid: u32, gid: u32) -> Result<(), WipeDomainError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| reseed_err(&e.to_string()))?;
    let result = (|| {
        f.write_all(data).map_err(|e| reseed_err(&e.to_string()))?;
        f.sync_all().map_err(|e| reseed_err(&e.to_string()))?;
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .map_err(|e| reseed_err(&e.to_string()))?;
        rustix::fs::chown(
            path,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(gid)),
        )
        .map_err(|e| reseed_err(&e.raw_os_error().to_string()))
    })();
    drop(f);
    result
}

/// `ReseedInstance` — rebuilds the protected-state skeleton for a new
/// instance identity: the state root with its four subdirectories, the
/// rebound config, a reseed marker, and an empty broker protected root.
/// Fresh TLS, signing, and grant state are created on next boot by
/// their owners; their absence here is the reseed proof, asserted by
/// [`verify_reseed_fresh`].
pub fn reseed_instance(
    input: &domain::ReseedInput,
    now: fn() -> OffsetDateTime,
    wiped_instance_id: &str,
    checkpoint_backup_id: &str,
) -> Result<(), WipeDomainError> {
    if input.instances_root.is_empty()
        || input.protected_parent.is_empty()
        || input.new_instance_id.is_empty()
        || input.config_bytes.is_empty()
    {
        return Err(reseed_err("incomplete input"));
    }
    let parsed =
        InstanceId::parse(&input.new_instance_id).map_err(|_| reseed_err("new instance id"))?;
    if parsed.to_string() != input.new_instance_id {
        return Err(reseed_err("new instance id"));
    }
    let state_root = format!("{}/{}", input.instances_root, input.new_instance_id);
    mkdir_owned(&state_root, input.instance_uid, input.instance_gid)
        .map_err(|_| reseed_err("state root"))?;
    for sub in ["data", "backups", "dependencies", "lifecycle"] {
        mkdir_owned(
            &format!("{state_root}/{sub}"),
            input.instance_uid,
            input.instance_gid,
        )
        .map_err(|_| reseed_err(sub))?;
    }
    write_owned(
        &format!("{state_root}/config.json"),
        &input.config_bytes,
        input.instance_uid,
        input.instance_gid,
    )
    .map_err(|_| reseed_err("config"))?;
    #[derive(Serialize)]
    struct Marker<'a> {
        new_instance_id: &'a str,
        wiped_instance_id: &'a str,
        checkpoint_backup: &'a str,
        reseeded_at: String,
        config_provenance: &'a str,
        tls_provenance: &'a str,
    }
    let marker = serde_json::to_string(&Marker {
        new_instance_id: &input.new_instance_id,
        wiped_instance_id,
        checkpoint_backup: checkpoint_backup_id,
        reseeded_at: rfc3339_now(now),
        config_provenance: "rebound-operator-document",
        tls_provenance: "fresh-on-next-boot",
    })
    .map_err(|_| reseed_err("marker"))?;
    write_owned(
        &format!("{state_root}/reseed.json"),
        format!("{marker}\n").as_bytes(),
        input.instance_uid,
        input.instance_gid,
    )
    .map_err(|_| reseed_err("marker"))?;
    let broker_instance = format!("{}/{}", input.protected_parent, input.new_instance_id);
    mkdir_owned(&broker_instance, input.broker_uid, input.broker_gid)
        .map_err(|_| reseed_err("broker root"))?;
    mkdir_owned(
        &format!("{broker_instance}/protected"),
        input.broker_uid,
        input.broker_gid,
    )
    .map_err(|_| reseed_err("broker protected"))?;
    Ok(())
}

/// `VerifyReseedFresh` — asserts the reseed produced new authority
/// state and no carried-over trust material: the new state root parses
/// as the new identity, and no TLS authority, signing, grant, or
/// ceremony state exists under either new root.
pub fn verify_reseed_fresh(
    state_root: &str,
    broker_protected_root: &str,
    new_instance_id: &str,
) -> Result<(), WipeDomainError> {
    let raw =
        std::fs::read(format!("{state_root}/config.json")).map_err(|_| reseed_err("config"))?;
    let cfg = central_infra::config::parse(&raw).map_err(|_| reseed_err("config"))?;
    if cfg.instance_id.to_string() != new_instance_id
        || cfg.paths.authoritative_state_root != state_root
    {
        return Err(reseed_err("config identity mismatch"));
    }
    for forbidden in [
        format!("{state_root}/ceremony-mode"),
        format!("{state_root}/grants"),
        format!("{state_root}/tls-authority.json"),
        format!("{broker_protected_root}/tls-authority.json"),
    ] {
        match std::fs::symlink_metadata(&forbidden) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(reseed_err("stale trust state survives")),
        }
    }
    Ok(())
}

/// `bindFreshBackupRepository` — binds the reseed's empty backups
/// directory to the new instance through the production binding APIs.
/// A reseed that cannot bind fails like any other reseed failure: the
/// wipe does not complete with a half-initialized instance.
fn bind_fresh_backup_repository(
    backups_root: &str,
    new_instance_id: &str,
) -> Result<(), WipeDomainError> {
    let fd = rustix::fs::open(
        backups_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| reseed_err("backups root"))?;
    crate::backup_repository::initialize_repository_binding(&fd, new_instance_id)
        .map_err(|_| reseed_err("repository binding"))?;
    Ok(())
}

/// `WriteWipeIntent` — durably records the wipe before destruction.
/// Owner is the instances-parent owner (root in production).
pub fn write_wipe_intent(
    instances_root: &str,
    intent: &WipeIntent,
    uid: u32,
    gid: u32,
) -> Result<(), WipeDomainError> {
    let raw = serde_json::to_string(intent).map_err(|e| reseed_err(&e.to_string()))?;
    write_owned(
        &format!(
            "{instances_root}/{}",
            domain::wipe_intent_file_name(&intent.operation_id)
        ),
        format!("{raw}\n").as_bytes(),
        uid,
        gid,
    )
}

/// `ReadWipeIntent` — loads the crash record for an operation, or
/// reports its absence. A present-but-unparseable record is corruption,
/// never ignored.
pub fn read_wipe_intent(
    instances_root: &str,
    operation_id: &str,
) -> Result<Option<WipeIntent>, WipeDomainError> {
    let path = format!(
        "{instances_root}/{}",
        domain::wipe_intent_file_name(operation_id)
    );
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(reseed_err(&e.to_string())),
    };
    let intent: WipeIntent =
        serde_json::from_slice(&raw).map_err(|e| WipeDomainError::IntentCorrupt(e.to_string()))?;
    if intent.operation_id != operation_id || intent.instance_id.is_empty() {
        return Err(WipeDomainError::IntentCorrupt(String::new()));
    }
    Ok(Some(intent))
}

/// `FindStaleIntent` — scans the parent for an intent naming an
/// instance whose state root is gone: the fingerprint of a wipe that
/// crashed between deletion and reseed. At most one instance may be
/// missing; more is operator repair territory, refused rather than
/// guessed.
pub fn find_stale_intent(instances_root: &str) -> Result<Option<WipeIntent>, WipeDomainError> {
    let entries = std::fs::read_dir(instances_root).map_err(|e| reseed_err(&e.to_string()))?;
    let mut found: Option<WipeIntent> = None;
    for entry in entries {
        let entry = entry.map_err(|e| reseed_err(&e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().is_ok_and(|t| t.is_dir()) || !domain::is_wipe_intent_file_name(&name) {
            continue;
        }
        let Ok(raw) = std::fs::read(format!("{instances_root}/{name}")) else {
            continue;
        };
        let Ok(intent) = serde_json::from_slice::<WipeIntent>(&raw) else {
            return Err(WipeDomainError::IntentCorrupt(String::new()));
        };
        if intent.instance_id.is_empty() {
            return Err(WipeDomainError::IntentCorrupt(String::new()));
        }
        match std::fs::symlink_metadata(&intent.state_root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if found.is_some() {
                    return Err(reseed_err(
                        "multiple crashed wipes; operator repair required",
                    ));
                }
                found = Some(intent);
            }
            _ => {}
        }
    }
    Ok(found)
}

/// `CompleteWipe` — writes the terminal result and removes the intent,
/// in that order: a crash between them leaves both, and the result's
/// presence marks the intent as already-decided. It also supersedes
/// every other intent naming the same wiped instance.
pub fn complete_wipe(
    instances_root: &str,
    result: &WipeResultRecord,
    uid: u32,
    gid: u32,
) -> Result<(), WipeDomainError> {
    let raw = serde_json::to_string(result).map_err(|e| reseed_err(&e.to_string()))?;
    write_owned(
        &format!(
            "{instances_root}/{}",
            domain::wipe_result_file_name(&result.operation_id)
        ),
        format!("{raw}\n").as_bytes(),
        uid,
        gid,
    )?;
    let entries = std::fs::read_dir(instances_root).map_err(|e| reseed_err(&e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| reseed_err(&e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().is_ok_and(|t| t.is_dir()) || !domain::is_wipe_intent_file_name(&name) {
            continue;
        }
        let Ok(raw) = std::fs::read(format!("{instances_root}/{name}")) else {
            continue;
        };
        let Ok(intent) = serde_json::from_slice::<WipeIntent>(&raw) else {
            continue;
        };
        if intent.instance_id == result.instance_id {
            match std::fs::remove_file(format!("{instances_root}/{name}")) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(reseed_err(&e.to_string())),
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Client — `client_linux.go`'s wipe half.
// ---------------------------------------------------------------------------

/// `WipeClientResult` mirrors the helper's `WipeResult` across the
/// socket. It carries identities and state only.
pub type WipeClientResult = WipeResult;

/// `WipeClientError` — only the stable exit class plus a whitelisted
/// reason token cross the boundary. Anything outside the whitelist is
/// folded away.
#[derive(Debug)]
pub struct WipeClientError {
    exit_code: i64,
    reason: String,
}

impl WipeClientError {
    /// The helper's exit class (2..=7; anything else folds to 6).
    #[must_use]
    pub fn exit_code(&self) -> i64 {
        self.exit_code
    }

    /// The whitelisted helper reason token, or empty when the helper
    /// reported nothing on the closed set.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl WipeClientError {
    /// Test-only constructor for the CLI's closed error-table tests
    /// (`cfg(test)` cannot reach across crates, so it is a documented
    /// hidden constructor instead).
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(exit_code: i64, reason: &str) -> Self {
        new_wipe_client_error(exit_code, reason)
    }
}

impl std::fmt::Display for WipeClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("helper: wipe failed")
    }
}

impl std::error::Error for WipeClientError {}

/// `DenySafeActiveWireReason` — the deny-safe gate's refusal token.
pub const DENY_SAFE_ACTIVE_WIRE_REASON: &str = "DENY_SAFE_ACTIVE";

fn retained_wipe_reason(reason: &str) -> String {
    match reason {
        r if r == DENY_SAFE_ACTIVE_WIRE_REASON
            || r == domain::REASON_WIPE_DENIED_SIGNED
            || r == domain::REASON_WIPE_CHECKPOINT_FAILED
            || r == domain::REASON_WIPE_APPARMOR_REFUSED
            || r == domain::REASON_WIPE_TARGET_INVALID
            || r == domain::REASON_WIPE_TARGET_LIVE
            || r == domain::REASON_WIPE_RESEED_FAILED
            || r == domain::REASON_WIPE_CEREMONY_REQUIRED
            || r == domain::REASON_WIPE_AUTHORITY_DENIED =>
        {
            r.to_owned()
        }
        _ => String::new(),
    }
}

fn new_wipe_client_error(exit_code: i64, reason: &str) -> WipeClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    WipeClientError {
        exit_code,
        reason: retained_wipe_reason(reason),
    }
}

/// `WipeClient` — `NewWipeClient`'s linux implementation: the
/// unprivileged CLI's whole view of the wipe verb.
pub struct WipeClient {
    socket_path: String,
}

impl WipeClient {
    /// `NewWipeClient`.
    #[must_use]
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `Wipe` — one bounded request/response exchange.
    pub fn wipe(
        &self,
        operation_id: &str,
        target_path: &str,
        checkpoint_backup_id: &str,
    ) -> Result<WipeClientResult, WipeClientError> {
        if self.socket_path.is_empty()
            || operation_id.is_empty()
            || target_path.is_empty()
            || checkpoint_backup_id.is_empty()
        {
            return Err(new_wipe_client_error(3, ""));
        }
        let mut conn = std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(|_| new_wipe_client_error(3, ""))?;
        let bound = Duration::from_secs(5);
        let _ = conn.set_read_timeout(Some(bound));
        let _ = conn.set_write_timeout(Some(bound));
        #[derive(Serialize)]
        struct Payload<'a> {
            target_path: &'a str,
            checkpoint_backup_id: &'a str,
        }
        let payload = serde_json::to_string(&Payload {
            target_path,
            checkpoint_backup_id,
        })
        .ok()
        .and_then(|s| serde_json::value::RawValue::from_string(s).ok());
        write_request(
            &mut conn,
            &Request {
                operation_id: operation_id.to_owned(),
                verb: super::verb::WIPE.to_owned(),
                payload,
            },
        )
        .map_err(|_| new_wipe_client_error(3, ""))?;
        let response = read_response(&mut conn).map_err(|_| new_wipe_client_error(3, ""))?;
        if response.outcome != "success" || response.exit_code != 0 {
            return Err(new_wipe_client_error(response.exit_code, &response.reason));
        }
        let payload = response
            .result
            .as_ref()
            .map(|r| r.get().as_bytes().to_vec())
            .unwrap_or_default();
        let result: WipeClientResult = super::backup::decode_exact_backup_read_result(&payload)
            .map_err(|_| new_wipe_client_error(6, ""))?;
        if result.operation_id != operation_id
            || result.wiped_instance_id.is_empty()
            || result.new_instance_id.is_empty()
            || result.checkpoint_backup_id != checkpoint_backup_id
        {
            return Err(new_wipe_client_error(response.exit_code, &response.reason));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubConfirmer {
        confirm: bool,
        consume: bool,
    }

    impl WipePamConfirmer for StubConfirmer {
        fn verify_and_consume(&self, _token: &str) -> bool {
            self.consume
        }
        fn confirm_wipe(
            &self,
            _peer: PeerIdentity,
            _deadline: Option<Instant>,
            _scope: &CeremonyScope,
            _op: &str,
        ) -> Option<Result<String, Failure>> {
            if self.confirm {
                Some(Ok("token".to_owned()))
            } else {
                Some(Err(Failure::denied("pam", "no")))
            }
        }
    }

    struct NoWipeCeremony;
    impl WipePamConfirmer for NoWipeCeremony {
        fn verify_and_consume(&self, _token: &str) -> bool {
            true
        }
    }

    struct StubEvaluator {
        current: bool,
    }
    impl WipeAdvisoryEvaluator for StubEvaluator {
        fn evaluate(
            &self,
        ) -> Result<
            (
                super::super::prepare::AdvisoryResult,
                super::super::prepare::AdvisoryAdmission,
            ),
            Failure,
        > {
            Ok((
                super::super::prepare::AdvisoryResult {
                    state: if self.current {
                        "current".to_owned()
                    } else {
                        "denied".to_owned()
                    },
                    code: String::new(),
                },
                super::super::prepare::AdvisoryAdmission::default(),
            ))
        }
    }

    struct StubCheckpoint {
        sealed: bool,
    }
    impl WipeCheckpointVerifier for StubCheckpoint {
        fn verify_sealed(
            &self,
            _deadline: Instant,
            _id: &str,
            _peer: &PeerIdentity,
        ) -> Result<(), Failure> {
            if self.sealed {
                Ok(())
            } else {
                Err(Failure::unavailable("checkpoint", "not sealed"))
            }
        }
    }

    fn fixture(confirm: bool, current: bool, sealed: bool) -> WipeHandlerImpl {
        WipeHandlerImpl::new(
            Some(Box::new(StubConfirmer {
                confirm,
                consume: true,
            })),
            Some(Box::new(StubEvaluator { current })),
            Some(Box::new(StubCheckpoint { sealed })),
            CeremonyScope {
                instance_id: "default".to_owned(),
                target_id: "postgres:central".to_owned(),
            },
            WipeRoots {
                instances_root: "/root/instances".to_owned(),
                protected_parent: "/root/protected".to_owned(),
                runtime_base: "/run/base".to_owned(),
                parent_uid: 0,
                parent_gid: 0,
                instance_uid: 501,
                instance_gid: 501,
            },
            AppArmorDeps {
                attr_current_path: "/nonexistent/attr".to_owned(),
                profile_path: "/nonexistent/profile".to_owned(),
                look_path: |name| Ok(PathBuf::from(name)),
                run: |_, _| Ok(()),
            },
        )
    }

    fn peer() -> PeerIdentity {
        PeerIdentity {
            uid: 1000,
            gid: 1000,
            pid: 4242,
        }
    }

    fn req(op: &str) -> WipeRequest {
        let id = InstanceId::new().to_string();
        WipeRequest {
            operation_id: op.to_owned(),
            target_path: format!("/root/instances/{id}"),
            checkpoint_backup_id: Uuid::now_v7().to_string(),
        }
    }

    /// Gate order: advisory denial precedes every ceremony — no prompt
    /// is shown for a doomed wipe.
    #[test]
    fn signed_denial_refuses_before_ceremony() {
        let handler = fixture(true, false, true);
        let op = Uuid::now_v7().to_string();
        let resp = handler.wipe(Instant::now() + Duration::from_secs(60), req(&op), &peer());
        assert_eq!(resp.outcome, "denied");
        assert_eq!(resp.exit_code, 7);
        assert_eq!(resp.reason, domain::REASON_WIPE_DENIED_SIGNED);
    }

    /// A confirmer that cannot run the wipe ceremony is refused as
    /// `WIPE_CEREMONY_REQUIRED`, never a fallback.
    #[test]
    fn missing_wipe_ceremony_refuses() {
        let handler = WipeHandlerImpl::new(
            Some(Box::new(NoWipeCeremony)),
            Some(Box::new(StubEvaluator { current: true })),
            Some(Box::new(StubCheckpoint { sealed: true })),
            CeremonyScope {
                instance_id: "default".to_owned(),
                target_id: "postgres:central".to_owned(),
            },
            WipeRoots {
                instances_root: "/root/instances".to_owned(),
                protected_parent: "/root/protected".to_owned(),
                runtime_base: "/run/base".to_owned(),
                parent_uid: 0,
                parent_gid: 0,
                instance_uid: 501,
                instance_gid: 501,
            },
            AppArmorDeps {
                attr_current_path: "/nonexistent/attr".to_owned(),
                profile_path: "/nonexistent/profile".to_owned(),
                look_path: |name| Ok(PathBuf::from(name)),
                run: |_, _| Ok(()),
            },
        );
        let op = Uuid::now_v7().to_string();
        let resp = handler.wipe(Instant::now() + Duration::from_secs(60), req(&op), &peer());
        assert_eq!(resp.reason, domain::REASON_WIPE_CEREMONY_REQUIRED);
    }

    /// An unsealed checkpoint refuses after the ceremony with
    /// `WIPE_CHECKPOINT_FAILED` — no state is touched.
    #[test]
    fn unsealed_checkpoint_refuses() {
        let handler = fixture(true, true, false);
        let op = Uuid::now_v7().to_string();
        let resp = handler.wipe(Instant::now() + Duration::from_secs(60), req(&op), &peer());
        assert_eq!(resp.reason, domain::REASON_WIPE_CHECKPOINT_FAILED);
    }

    /// A malformed target fails before the ceremony.
    #[test]
    fn malformed_target_fails_before_ceremony() {
        let handler = fixture(false, true, true);
        let op = Uuid::now_v7().to_string();
        let mut r = req(&op);
        r.target_path = "relative/not/abs".to_owned();
        let resp = handler.wipe(Instant::now() + Duration::from_secs(60), r, &peer());
        assert_eq!(resp.exit_code, 2);
        assert_eq!(resp.reason, domain::REASON_WIPE_TARGET_INVALID);
    }

    /// `parse_wipe_request` — strict payload, both fields required,
    /// unknown fields refused.
    #[test]
    fn parse_wipe_request_rules() {
        let req = |payload: &str| Request {
            operation_id: "op".to_owned(),
            verb: "wipe".to_owned(),
            payload: serde_json::value::RawValue::from_string(payload.to_owned()).ok(),
        };
        assert!(parse_wipe_request(&req("{}")).is_err());
        assert!(
            parse_wipe_request(&req(
                r#"{"target_path":"/x","checkpoint_backup_id":"b","extra":1}"#
            ))
            .is_err()
        );
        assert!(
            parse_wipe_request(&req(r#"{"target_path":"/x","checkpoint_backup_id":"b"}"#)).is_ok()
        );
        assert!(parse_wipe_request(&req("")).is_err());
    }

    /// `ensure_unconfined` — unconfined + absent profile needs no
    /// tooling; a profile is removed then re-verified.
    #[test]
    fn ensure_unconfined_states() {
        let dir = std::env::temp_dir().join(format!("wipe-aa-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let attr = dir.join("attr");
        let profile = dir.join("profile");
        std::fs::write(&attr, "unconfined\n").unwrap();
        let deps = |profile_path: PathBuf| AppArmorDeps {
            attr_current_path: attr.to_string_lossy().into_owned(),
            profile_path: profile_path.to_string_lossy().into_owned(),
            look_path: |name| Ok(PathBuf::from(name)),
            run: |_, _| Ok(()),
        };
        assert_eq!(
            ensure_unconfined(&deps(dir.join("absent-profile"))).unwrap(),
            AppArmorState::NotConfined
        );
        std::fs::write(&profile, "profile x {}\n").unwrap();
        assert_eq!(
            ensure_unconfined(&deps(profile.clone())).unwrap(),
            AppArmorState::ProfileRemoved
        );
        assert!(!profile.exists());
        std::fs::write(&attr, "central-sandbox-launcher (enforce)\n").unwrap();
        assert!(ensure_unconfined(&deps(dir.join("absent-profile"))).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `remove_tree` deletes only `<root>/<instance-id>` and verifies
    /// absence — the prefix+UUID checks make an arbitrary delete
    /// inexpressible.
    #[test]
    fn remove_tree_scoped_and_verified() {
        let dir = std::env::temp_dir().join(format!("wipe-rm-{}", Uuid::now_v7()));
        let id = InstanceId::new().to_string();
        let target = dir.join(&id);
        std::fs::create_dir_all(target.join("sub")).unwrap();
        assert!(remove_tree(dir.to_str().unwrap(), &id).is_ok());
        assert!(!target.exists());
        assert!(remove_tree(dir.to_str().unwrap(), "not-an-id").is_err());
        assert!(remove_tree("relative", &id).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Intent → stale-discovery → complete round-trip: a crashed wipe
    /// leaves exactly one discoverable intent; `complete_wipe`
    /// supersedes it.
    #[test]
    fn wipe_intent_crash_cycle() {
        let dir = std::env::temp_dir().join(format!("wipe-int-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.to_str().unwrap().to_owned();
        let id = InstanceId::new().to_string();
        let intent = WipeIntent {
            operation_id: "op-1".to_owned(),
            instance_id: id.clone(),
            checkpoint_backup_id: "b".to_owned(),
            state_root: format!("{root}/{id}"),
            broker_instance_dir: format!("{root}/../protected/{id}"),
            started_at: "t".to_owned(),
            config_json: "{}".to_owned(),
        };
        write_wipe_intent(
            &root,
            &intent,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
        .unwrap();
        // The intent is not stale while the state root exists.
        std::fs::create_dir_all(dir.join(&id)).unwrap();
        assert!(find_stale_intent(&root).unwrap().is_none());
        // Crash between deletion and reseed: the intent goes stale.
        std::fs::remove_dir_all(dir.join(&id)).unwrap();
        let stale = find_stale_intent(&root).unwrap().unwrap();
        assert_eq!(stale.operation_id, "op-1");
        complete_wipe(
            &root,
            &WipeResultRecord {
                operation_id: "op-1".to_owned(),
                instance_id: id.clone(),
                new_instance_id: InstanceId::new().to_string(),
                checkpoint_backup_id: "b".to_owned(),
                apparmor: AppArmorState::NotConfined,
                resumed_after_crash: true,
                completed_at: "t2".to_owned(),
                reason: "ok".to_owned(),
            },
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
        .unwrap();
        assert!(find_stale_intent(&root).unwrap().is_none());
        assert!(dir.join("wipe-op-1.result.json").exists());
        assert!(read_wipe_intent(&root, "op-1").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
