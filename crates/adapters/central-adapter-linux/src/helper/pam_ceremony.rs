//! `pam_linux.go`'s PAM half + `pam.go`'s interface — `PamConfirmer`:
//! fresh PAM against the socket peer, then the physical-console
//! ceremony, then a minted one-use token. In grant mode (ADR 0028) the
//! console exchange is replaced by spending one helper-verified grant;
//! token minting and one-use consumption are identical in both modes.

use super::grant::{GrantKind, GrantScope, GrantStore};
use super::prepare::ConfirmationBinding;
use super::tty_ceremony::*;
use super::{PeerIdentity, read_boot_id};
use crate::sys::{pam, tty};
use central_foundation::failure::Failure;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// `PAMSession`.
#[derive(Debug, Clone)]
pub struct PamSession {
    pub valid: bool,
    pub username: String,
    pub uid: u32,
}

/// `user.LookupId` over `/etc/passwd` — the pure-Go resolver's own
/// source; NSS plugins are outside this build's model, exactly as a
/// statically-linked Go helper would resolve.
fn username_for_uid(uid: u32) -> Result<String, Failure> {
    let raw = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| Failure::internal("sys_pam_lookup", format!("pam: user lookup: {e}")))?;
    for line in raw.lines() {
        let mut fields = line.split(':');
        let (name, _pw, id) = match (fields.next(), fields.next(), fields.next()) {
            (Some(n), Some(p), Some(i)) => (n, p, i),
            _ => continue,
        };
        if id.parse::<u32>().ok() == Some(uid) {
            return Ok(name.to_owned());
        }
    }
    Err(Failure::internal(
        "sys_pam_lookup",
        format!("pam: user lookup: unknown uid {uid}"),
    ))
}

/// `Authenticate` — resolve the subject from the Unix peer only, collect
/// the password on that peer's physical console, run the PAM
/// conversation. Fresh per call: authentication is never reused.
pub fn authenticate(peer: PeerIdentity, deadline: Option<Instant>) -> Result<PamSession, Failure> {
    if !peer.available() {
        return Err(Failure::denied(
            "sys_pam_auth",
            "pam: Unix peer is unavailable",
        ));
    }
    let username = username_for_uid(peer.uid)?;
    let pid = rustix::process::Pid::from_raw(peer.pid)
        .ok_or_else(|| Failure::denied("sys_pam_auth", "pam: Unix peer is unavailable"))?;
    // The prompt's own failure stays a console failure — no credential
    // was ever collected, so PAM was never asked anything.
    let password = tty::prompt_password(pid, deadline, None)?;
    pam::authenticate(&username, &password)?;
    Ok(PamSession {
        valid: true,
        username,
        uid: peer.uid as i32 as u32,
    })
}

struct ConfirmationRecord {
    binding: String,
    consumed: bool,
}

/// `pamConfirmer` — `NewPAMConfirmer` in physical mode,
/// `NewPAMConfirmerWithGrants` in grant mode.
pub struct PamConfirmer {
    used: Mutex<HashMap<String, ConfirmationRecord>>,
    grants: Option<GrantStore>,
    grant_scope: GrantScope,
}

impl Default for PamConfirmer {
    fn default() -> Self {
        Self::new()
    }
}

impl PamConfirmer {
    /// `NewPAMConfirmer` — physical_tty mode.
    pub fn new() -> Self {
        PamConfirmer {
            used: Mutex::new(HashMap::new()),
            grants: None,
            grant_scope: GrantScope::default(),
        }
    }

    /// `NewPAMConfirmerWithGrants` — instance/target are the installed
    /// composition's, the same identities the TTY phrases are built from.
    pub fn with_grants(store: GrantStore, instance_id: &str, target_id: &str) -> Self {
        PamConfirmer {
            used: Mutex::new(HashMap::new()),
            grants: Some(store),
            grant_scope: GrantScope {
                instance_id: instance_id.to_owned(),
                target_id: target_id.to_owned(),
                ..GrantScope::default()
            },
        }
    }

    /// `ceremony` — the single dispatch between the two modes. The
    /// argument list is upstream's `pamConfirmer.ceremony` signature —
    /// grouping it into a struct would rename the seam, so the arity
    /// stays.
    #[allow(clippy::too_many_arguments)]
    fn ceremony(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        kind: GrantKind,
        scope: GrantScope,
        operation_id: &str,
        tty_fn: impl FnOnce() -> Result<(), Failure>,
        failure: &str,
    ) -> Result<(), Failure> {
        if self.grants.is_none() {
            let session =
                authenticate(peer, deadline).map_err(tty::describe_authentication_failure)?;
            if !session.valid {
                return Err(Failure::denied(
                    "sys_pam_auth",
                    "pam: authentication did not establish a valid session",
                ));
            }
            return tty_fn().map_err(|e| {
                Failure::denied(
                    "sys_tty_ceremony",
                    format!("tty: {failure} failed: {}", e.message()),
                )
            });
        }
        if !peer.available() {
            return Err(Failure::denied(
                "sys_grant_peer",
                "grant: Unix peer is unavailable",
            ));
        }
        let boot_id = read_boot_id()?;
        let mut scope = scope;
        if scope.instance_id.is_empty() {
            scope = self.grant_scope.clone();
        }
        scope.kind = kind;
        scope.operation_id = operation_id.to_owned();
        self.grants
            .as_ref()
            .map(|g| g.consume(&scope, &boot_id, peer.uid, peer.pid))
            .and_then(|r| r.ok())
            .map(|_| ())
            .ok_or_else(|| {
                Failure::denied(
                    "sys_grant_denied",
                    format!("grant: {failure} failed: grant: no valid grant for this operation"),
                )
            })
    }

    fn new_confirmation_token(&self) -> Result<String, Failure> {
        self.new_bound_confirmation_token("")
    }

    fn new_bound_confirmation_token(&self, binding: &str) -> Result<String, Failure> {
        let mut raw = [0u8; 32];
        rustix::rand::getrandom(&mut raw, rustix::rand::GetRandomFlags::empty()).map_err(|e| {
            Failure::internal(
                "sys_pam_token",
                format!("pam: generate confirmation nonce: {e}"),
            )
        })?;
        // `base64.RawURLEncoding.EncodeToString` — upstream's token form
        // (pam_linux.go's ConfirmationToken).
        let token = crate::broker::wire::b64_url_raw_encode(&raw);
        self.used.lock().unwrap_or_else(|e| e.into_inner()).insert(
            token.clone(),
            ConfirmationRecord {
                binding: binding.to_owned(),
                consumed: false,
            },
        );
        Ok(token)
    }

    /// `VerifyAndConsume` — an unbound token only; a bound token is
    /// refused here rather than spent.
    pub fn verify_and_consume(&self, token: &str) -> bool {
        self.consume(token, "")
    }

    /// `VerifyAndConsumePrepare` — consume only against the binding the
    /// token was minted for.
    pub fn verify_and_consume_prepare(&self, token: &str, binding: &ConfirmationBinding) -> bool {
        self.consume(token, &binding.fingerprint())
    }

    fn consume(&self, token: &str, binding: &str) -> bool {
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        match used.get_mut(token) {
            Some(record) if !record.consumed && record.binding == binding => {
                record.consumed = true;
                true
            }
            _ => false,
        }
    }

    /// `Confirm` — the lifecycle ceremony: PAM then `CONFIRM <code>`.
    pub fn confirm(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        op_id: &str,
    ) -> Result<String, Failure> {
        self.ceremony(
            peer,
            deadline,
            GrantKind::Lifecycle,
            GrantScope::default(),
            op_id,
            || perform_tty_ceremony(peer, deadline, op_id, ""),
            "ceremony",
        )?;
        self.new_confirmation_token()
    }

    /// `ConfirmPrepare` — same ceremony, token bound to this request.
    pub fn confirm_prepare(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        op_id: &str,
        binding: &ConfirmationBinding,
    ) -> Result<String, Failure> {
        if binding.fingerprint().is_empty() {
            return Err(Failure::invalid(
                "sys_pam_binding",
                "pam: prepare confirmation requires a binding",
            ));
        }
        self.ceremony(
            peer,
            deadline,
            GrantKind::Prepare,
            GrantScope::default(),
            op_id,
            || perform_tty_ceremony(peer, deadline, op_id, ""),
            "ceremony",
        )?;
        self.new_bound_confirmation_token(&binding.fingerprint())
    }

    /// `ConfirmInit` — the genesis ceremony; a grant-mode confirmer
    /// refuses (init grants authorize genesis in the handler, never
    /// through this confirmer).
    pub fn confirm_init(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        operation_id: &str,
    ) -> Result<String, Failure> {
        if operation_id.is_empty() {
            return Err(Failure::invalid(
                "sys_tty_scope",
                "tty: init confirmation needs an operation",
            ));
        }
        if self.grants.is_some() {
            return Err(Failure::denied(
                "sys_grant_init",
                "grant: no grant kind authorizes init via ConfirmInit (init grants authorize genesis only)",
            ));
        }
        self.ceremony(
            peer,
            deadline,
            GrantKind::Empty,
            GrantScope::default(),
            operation_id,
            || perform_init_tty_ceremony(peer, deadline),
            "init ceremony",
        )?;
        self.new_confirmation_token()
    }
}

impl super::lifecycle::LifecycleConfirmer for PamConfirmer {
    fn confirm(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        op_id: &str,
    ) -> Result<String, Failure> {
        PamConfirmer::confirm(self, peer, deadline, op_id)
    }
    fn verify_and_consume(&self, token: &str) -> bool {
        PamConfirmer::verify_and_consume(self, token)
    }
}

impl super::init::InitConfirmer for PamConfirmer {
    fn confirm_init(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        operation_id: &str,
    ) -> Result<String, Failure> {
        PamConfirmer::confirm_init(self, peer, deadline, operation_id)
    }
    fn verify_and_consume(&self, token: &str) -> bool {
        PamConfirmer::verify_and_consume(self, token)
    }
}

/// `preparePAMConfirmer` — the binding-bound confirmation the prepare
/// handler requires. Both halves already exist as inherent methods:
/// the token is minted for a `ConfirmationBinding` fingerprint and
/// consumed only against that same fingerprint.
impl super::prepare::PreparePamConfirmer for PamConfirmer {
    fn confirm_prepare(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        op_id: &str,
        binding: &ConfirmationBinding,
    ) -> Result<String, Failure> {
        PamConfirmer::confirm_prepare(self, peer, deadline, op_id, binding)
    }
    fn verify_and_consume_prepare(&self, token: &str, binding: &ConfirmationBinding) -> bool {
        PamConfirmer::verify_and_consume_prepare(self, token, binding)
    }
}

/// `wipePAMConfirmer`/`deletePAMConfirmer`/`prunePAMConfirmer` — each
/// destructive handler accepts only the exact ceremony of its kind,
/// mapped to `Some` here and `None` in stand-ins. Upstream's failed
/// type assertions are the `Option` returns.
impl super::wipe::WipePamConfirmer for PamConfirmer {
    fn verify_and_consume(&self, token: &str) -> bool {
        PamConfirmer::verify_and_consume(self, token)
    }
    fn confirm_wipe(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        scope: &super::grant::CeremonyScope,
        op_id: &str,
    ) -> Option<Result<String, Failure>> {
        Some(PamConfirmer::confirm_wipe(
            self, peer, deadline, scope, op_id,
        ))
    }
}

impl super::delete::DeletePamConfirmer for PamConfirmer {
    fn verify_and_consume(&self, token: &str) -> bool {
        PamConfirmer::verify_and_consume(self, token)
    }
    fn confirm_backup_delete(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        scope: &super::grant::CeremonyScope,
        op_id: &str,
    ) -> Option<Result<String, Failure>> {
        Some(PamConfirmer::confirm_backup_delete(
            self, peer, deadline, scope, op_id,
        ))
    }
}

impl super::prune::PrunePamConfirmer for PamConfirmer {
    fn verify_and_consume(&self, token: &str) -> bool {
        PamConfirmer::verify_and_consume(self, token)
    }
    fn confirm_backup_prune(
        &self,
        peer: PeerIdentity,
        deadline: Option<Instant>,
        scope: &super::grant::CeremonyScope,
        plan_id: &str,
    ) -> Option<Result<String, Failure>> {
        Some(PamConfirmer::confirm_backup_prune(
            self, peer, deadline, scope, plan_id,
        ))
    }
}

macro_rules! destructive_confirms {
    ($($name:ident => ($kind:ident, $tty:ident, $err:literal, $label:literal);)*) => {
        $(
            /// Upstream's same-named `Confirm*` — the one ceremony of
            /// this destructive kind, with its own phrase.
            pub fn $name(
                &self,
                peer: PeerIdentity,
                deadline: Option<Instant>,
                scope: &super::grant::CeremonyScope,
                operation_id: &str,
            ) -> Result<String, Failure> {
                if scope.instance_id.is_empty() || scope.target_id.is_empty() || operation_id.is_empty() {
                    return Err(Failure::invalid("sys_tty_scope", concat!("tty: ", $err, " confirmation scope is incomplete")));
                }
                self.ceremony(
                    peer,
                    deadline,
                    GrantKind::$kind,
                    GrantScope { instance_id: scope.instance_id.clone(), target_id: scope.target_id.clone(), ..GrantScope::default() },
                    operation_id,
                    || $tty(peer, deadline, &scope.instance_id, &scope.target_id, operation_id),
                    concat!($label, " ceremony"),
                )?;
                self.new_confirmation_token()
            }
        )*
    };
}

impl PamConfirmer {
    destructive_confirms! {
        confirm_migration_reset => (MigrationReset, perform_migration_reset_tty_ceremony, "reset", "reset");
        confirm_restore_apply => (RestoreApply, perform_restore_apply_tty_ceremony, "restore", "restore");
        confirm_restore_abandon => (RestoreAbandon, perform_restore_abandon_tty_ceremony, "abandon", "abandon");
        confirm_wipe => (Wipe, perform_wipe_tty_ceremony, "wipe", "wipe");
        confirm_backup_export => (BackupExport, perform_export_tty_ceremony, "export", "export");
        confirm_backup_import => (BackupImport, perform_import_tty_ceremony, "import", "import");
        confirm_backup_delete => (BackupDelete, perform_delete_tty_ceremony, "delete", "delete");
        confirm_backup_prune => (BackupPrune, perform_prune_tty_ceremony, "prune", "prune");
        confirm_security_rescue => (SecurityRescue, perform_rescue_tty_ceremony, "rescue", "rescue");
        confirm_maintenance_apply => (MaintenanceApply, perform_maintenance_apply_tty_ceremony, "maintenance-apply", "maintenance-apply");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The minted confirmation token is upstream's
    /// `base64.RawURLEncoding` of 32 random bytes — 43 chars, no
    /// padding, URL-safe alphabet — and it verifies exactly once.
    #[test]
    fn confirmation_token_is_base64url_and_single_use() {
        let confirmer = PamConfirmer::new();
        let token = confirmer.new_confirmation_token().unwrap();
        assert_eq!(token.len(), 43);
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_eq!(
            crate::broker::wire::b64_url_raw_decode(&token).map(|v| v.len()),
            Some(32)
        );
        assert!(confirmer.verify_and_consume(&token));
        assert!(!confirmer.verify_and_consume(&token));
    }
}
