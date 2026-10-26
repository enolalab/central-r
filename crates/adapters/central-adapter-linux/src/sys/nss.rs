//! `sys::nss` — the shared Name Service Switch lookups (`getpwnam` /
//! `getgrnam`) the privileged daemons use to resolve the locked
//! `central-*` identities. The `unsafe` libc calls live in
//! [`super::audited`]; this module is the `forbid(unsafe_code)` front
//! door.
//!
//! Provenance: the wrappers are the `central-harness-launcherd`
//! `sys.rs` NSS pair carried forward verbatim (R5 task 14, open
//! decision D5), now shared so the helper's managed-browser launch
//! resolves `central-browser` through the same audited site.

use std::ffi::{CStr, CString};

/// One `passwd` record, reduced to what the daemons need.
#[derive(Debug, Clone)]
pub struct Passwd {
    /// `pw_uid`.
    pub uid: u32,
    /// `pw_gid`.
    pub gid: u32,
    /// `pw_name`.
    pub name: CString,
    /// `pw_dir`.
    pub home: CString,
}

/// `getpwnam(3)` — user name → [`Passwd`], `None` when absent.
#[must_use]
pub fn getpwnam(name: &CStr) -> Option<Passwd> {
    super::audited::getpwnam(name).map(|(uid, gid, name, home)| Passwd {
        uid,
        gid,
        name,
        home,
    })
}

/// `getpwnam(3)` by `&str` — `None` on a missing user or a name with
/// an interior NUL (which cannot name a user anyway).
#[must_use]
pub fn getpwnam_str(name: &str) -> Option<Passwd> {
    let c = CString::new(name).ok()?;
    getpwnam(&c)
}

/// `getgrnam(3)` — group name → gid, `None` when absent or the name
/// carries an interior NUL.
#[must_use]
pub fn getgrnam(name: &CStr) -> Option<u32> {
    super::audited::getgrnam(name)
}

/// `getgrnam(3)` by `&str`.
#[must_use]
pub fn getgrnam_str(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    getgrnam(&c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon's own user resolves; a name that cannot exist
    /// returns `None` rather than an error path.
    #[test]
    fn getpwnam_resolves_and_misses() {
        let self_uid = rustix::process::geteuid().as_raw();
        let root = getpwnam_str("root").expect("root resolves");
        assert_eq!(root.uid, 0);
        if self_uid == 0 {
            assert_eq!(root.gid, 0);
        }
        assert!(getpwnam_str("central-no-such-user-definitely").is_none());
        assert!(getpwnam_str("bad\0name").is_none());
    }

    /// The daemon's own group resolves; missing names return `None`.
    #[test]
    fn getgrnam_resolves_and_misses() {
        let root = getgrnam_str("root").expect("root group resolves");
        assert_eq!(root, 0);
        assert!(getgrnam_str("central-no-such-group-definitely").is_none());
    }
}
