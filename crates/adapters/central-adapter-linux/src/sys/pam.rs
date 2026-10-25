//! `pam` — the safe front door of the PAM boundary (R5 task 5,
//! decision D1): upstream `internal/adapter/authority/helper/
//! pam_linux.go`'s `authenticatePAM`.
//!
//! The raw `extern "C"` surface lives in [`sys::audited::pam_ffi`];
//! this module owns the observable contract on top of it:
//!
//! - the service name is `central-helper` — the one
//!   `packaging/install/install.sh` writes `/etc/pam.d/central-helper`
//!   for, hard-coded at upstream's call site;
//! - an empty username or secret is refused *before* libpam is asked
//!   anything (`sys_pam_credential`, upstream's "physical TTY password
//!   is required"), so a credential collection failure can never be
//!   reported as an authentication failure;
//! - every non-`PAM_SUCCESS` result maps to the closed denial
//!   envelope `sys_pam_auth` — `denied`, with the upstream message
//!   shape `pam: authentication failed (code N)`. No result code maps
//!   to anything but success-or-denial.
//!
//! The secret is carried in a `Zeroizing<Vec<u8>>` for the duration of
//! the call, NUL-terminated in place and borrowed as a `CStr` with no
//! copy, so the caller's buffer — and the copies libpam makes — are
//! the only places the password ever lives, and ours is wiped on
//! every exit path including panic.
//!
//! [`sys::audited::pam_ffi`]: crate::sys::audited::pam_ffi

use std::ffi::{CStr, CString, NulError};

use central_foundation::failure::Failure;
use zeroize::Zeroizing;

use crate::sys::audited::pam_ffi::{self, PAM_SUCCESS};

/// The PAM service name, byte-exact upstream's
/// `C.CString("central-helper")` call site. The installed
/// `/etc/pam.d/central-helper` pulls in `common-auth` +
/// `common-account`.
pub const PAM_SERVICE: &str = "central-helper";

/// `authenticatePAM` — run the PAM conversation for `username` with
/// `secret` against the `central-helper` service.
///
/// `secret` is a byte string, not a `&str`: the password is whatever
/// the operator typed at the console, and upstream hands the bytes to
/// libpam untranslated. An interior NUL is refused (`sys_pam_credential`)
/// — a C string cannot carry it, and silently truncating a credential
/// is worse than refusing it.
///
/// # Errors
/// `sys_pam_credential` (`Invalid`) when `username` or `secret` is
/// empty or cannot be carried in a C string; `sys_pam_auth`
/// (`Denied`) for every non-`PAM_SUCCESS` result — the closed denial
/// envelope.
pub fn authenticate(username: &str, secret: &[u8]) -> Result<(), Failure> {
    authenticate_service(PAM_SERVICE, username, secret)
}

/// `authenticate` against a caller-chosen service — the same contract
/// as [`authenticate`] with the service name lifted. Exists so the
/// boundary can be exercised against a test PAM service without
/// hard-coding it into the production path's call sites; production
/// callers use [`authenticate`].
///
/// `pub(crate)` until a cross-crate caller exists — the service name
/// is not part of the exported surface.
///
/// # Errors
/// As [`authenticate`].
pub(crate) fn authenticate_service(
    service: &str,
    username: &str,
    secret: &[u8],
) -> Result<(), Failure> {
    // Upstream checks emptiness before building the C strings: the
    // refusal is "the credential was never collected", and folding it
    // into the PAM result would make a collection failure read as an
    // authentication failure.
    if username.is_empty() || secret.is_empty() {
        return Err(Failure::invalid(
            "sys_pam_credential",
            "pam: physical TTY password is required",
        ));
    }
    let cstring = |what: &str, bytes: &[u8]| -> Result<CString, Failure> {
        CString::new(bytes).map_err(|_: NulError| {
            Failure::invalid(
                "sys_pam_credential",
                format!("pam: {what} cannot be carried in a C string"),
            )
        })
    };
    let service = cstring("service name", service.as_bytes())?;
    let user = cstring("username", username.as_bytes())?;
    // Zeroizing wraps the allocation: the secret is wiped on every
    // return path, panic included — the FFI call below is the only
    // place it is ever exposed. The buffer is sized for the NUL
    // terminator up front — a growth realloc would abandon a copy of
    // the cleartext in the freed allocation — so no un-wiped copy of
    // the password exists.
    let mut buf = Zeroizing::new(Vec::with_capacity(secret.len() + 1));
    buf.extend_from_slice(secret);
    if buf.contains(&0) {
        return Err(Failure::invalid(
            "sys_pam_credential",
            "pam: password cannot be carried in a C string",
        ));
    }
    buf.push(0);
    let secret = buf;
    let secret = CStr::from_bytes_with_nul(secret.as_slice()).map_err(|_| {
        Failure::invalid(
            "sys_pam_credential",
            "pam: password cannot be carried in a C string",
        )
    })?;

    pam_result(pam_ffi::authenticate(&service, &user, secret))
}

/// The closed denial envelope: `PAM_SUCCESS` → `Ok`, every other code
/// → `Denied` with upstream's message shape. Unknown codes deny like
/// known ones — there is no result libpam can return that maps to
/// success except success.
fn pam_result(result: i32) -> Result<(), Failure> {
    if result == PAM_SUCCESS {
        Ok(())
    } else {
        Err(Failure::denied(
            "sys_pam_auth",
            format!("pam: authentication failed (code {result})"),
        ))
    }
}

#[cfg(test)]
mod tests {
    //! Portable side of the PAM boundary: the denial envelope and the
    //! pre-PAM credential refusal. The live-service case skips when
    //! the host has no `central-helper` PAM service configured —
    //! upstream's `pam` build tag is what skips there; checking the
    //! service file is the honest equivalent here.

    use super::*;

    /// Empty username or empty secret is refused before libpam is
    /// ever invoked — the error names the missing credential, never
    /// an authentication.
    #[test]
    fn empty_credentials_refuse_before_pam() {
        for (user, secret) in [
            ("", b"x".as_slice()),
            ("operator", b"".as_slice()),
            ("", b"".as_slice()),
        ] {
            let err = authenticate(user, secret).unwrap_err();
            assert_eq!(err.code(), "sys_pam_credential");
            assert!(err.message().contains("physical TTY password is required"));
        }
    }

    /// A credential that cannot ride a C string is refused, not
    /// truncated: `CString::new` rejects the interior NUL and so do
    /// we.
    #[test]
    fn interior_nul_credentials_are_refused_not_truncated() {
        let err = authenticate_service("central-helper", "op\0extra", b"secret").unwrap_err();
        assert_eq!(err.code(), "sys_pam_credential");
        let err = authenticate_service("central-helper", "op", b"sec\0ret").unwrap_err();
        assert_eq!(err.code(), "sys_pam_credential");
    }

    /// Every non-success PAM code lands in the same closed denial
    /// envelope — auth error, conversation error, and codes PAM does
    /// not even define. Only `PAM_SUCCESS` (0) is ever `Ok`.
    #[test]
    fn every_non_success_code_is_a_closed_denial() {
        assert!(pam_result(0).is_ok());
        for code in [1, 6, 7, 19, 28, 99, -1] {
            let err = pam_result(code).unwrap_err();
            assert_eq!(err.code(), "sys_pam_auth");
            assert_eq!(err.kind(), central_foundation::failure::FailureKind::Denied);
            assert!(
                err.message()
                    .contains(&format!("pam: authentication failed (code {code})")),
                "code {code} lost its envelope: {}",
                err.message()
            );
        }
    }

    /// The live path: against a host with `/etc/pam.d/central-helper`
    /// configured, a wrong password denies (never errors open); on a
    /// host without it, the run skips — upstream's `pam` build tag
    /// performs this same gating, and the install is what writes the
    /// service file.
    #[test]
    fn authenticate_against_live_service_denies_wrong_secret_or_skips() {
        if !std::path::Path::new("/etc/pam.d/central-helper").exists() {
            eprintln!(
                "SKIP: no /etc/pam.d/central-helper on this host; \
                 the live PAM authentication path is not being exercised"
            );
            return;
        }
        let err = authenticate("root", b"definitely-not-the-password-t5").unwrap_err();
        assert_eq!(err.code(), "sys_pam_auth");
        assert!(err.message().contains("pam: authentication failed"));
    }
}
