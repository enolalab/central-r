//! Audited syscall boundary (workflow §5.2; R5 decision D2).
//!
//! Every `unsafe` block of `central-adapter-linux` lives behind a named
//! safe wrapper here — the sites rustix 1.1 has no safe API for:
//!
//! - [`install_filter`] — `seccomp(SECCOMP_SET_MODE_FILTER, TSYNC, prog)`
//!   (upstream `hardening.go`'s `unix.Syscall(unix.SYS_SECCOMP, …)`;
//!   rustix's `thread::set_secure_computing_mode` covers only the strict
//!   mode, not a `sock_fprog` install, so the call goes through `libc`
//!   exactly as D2 decided).
//! - [`unshare`] — `unshare(flags)`: rustix marks
//!   [`rustix::thread::unshare_unsafe`] `unsafe` because the
//!   `CLONE_FILES`/`CLONE_FS` flags can detach the caller's descriptor
//!   table; [`sys::namespace`] admits only `CLONE_NEW*` namespace flags,
//!   so that hazard is statically excluded at the call site.
//! - [`pam_ffi`] — the hand-written Linux-PAM FFI (R5 task 5, decision
//!   D1): `pam_start` → `pam_authenticate` → `pam_end` and the
//!   conversation callback, byte-exact the upstream cgo shim
//!   (`internal/adapter/authority/helper/pam_linux.go`). `sys::pam`
//!   is the safe front door.
//!
//! [`sys::namespace`]: crate::sys::namespace
//! [`pam_ffi`]: self::pam_ffi

#![allow(unsafe_code)]

use rustix::io::Errno;

/// The current `errno` value after a libc call reported `-1`.
pub(crate) fn last_errno() -> Errno {
    Errno::from_io_error(&std::io::Error::last_os_error()).unwrap_or(Errno::INVAL)
}

/// `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, prog)` —
/// install `prog` on every thread of the calling process
/// (`sys::seccomp::install`). `TSYNC` is upstream's flag and the only
/// honest install for a daemon: a filter that covers only the calling
/// thread would leave the broker's other threads unfiltered.
///
/// `prog` must point at a live `sock_filter` array — the caller
/// (`sys::seccomp`) builds it from a `Vec<libc::sock_filter>` that
/// outlives the call; the kernel copies the program before returning,
/// so no reference is retained.
pub(crate) fn install_filter(prog: &libc::sock_fprog) -> Result<(), Errno> {
    // SAFETY: `prog` is a reference to a live `sock_fprog` whose
    // `filter` pointer names a `sock_filter` array of `len` entries —
    // `sys::seccomp::install` builds it from a slice and the kernel
    // copies the program synchronously, so the pointer cannot dangle
    // and no aliased mutation races the read. `SYS_seccomp` with
    // SET_MODE_FILTER|TSYNC installs the filter on all threads of this
    // process; it does not touch user memory beyond `prog` itself.
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            prog,
        )
    };
    if r != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `unshare(flags)` — rustix's safe `unshare` is deprecated in favour of
/// `unshare_unsafe`, which is `unsafe` only because `CLONE_FILES` /
/// `CLONE_FS` would detach the caller's descriptor table. The wrapper
/// takes [`sys::namespace::NamespaceFlags`], whose bits can only ever
/// hold `CLONE_NEW*` namespace flags, so that hazard is statically
/// excluded at the type level.
///
/// [`sys::namespace::NamespaceFlags`]: crate::sys::namespace::NamespaceFlags
pub(crate) fn unshare(flags: crate::sys::namespace::NamespaceFlags) -> Result<(), Errno> {
    let flags = flags.bits();
    debug_assert_eq!(
        flags & !crate::sys::namespace::NamespaceFlags::ALL.bits(),
        rustix::thread::UnshareFlags::empty(),
        "NamespaceFlags carries only CLONE_NEW* bits by construction"
    );
    // SAFETY: `flags` contains only `CLONE_NEW*` namespace bits —
    // `NamespaceFlags`'s private constructor admits nothing else — so
    // `FILES`/`FS`, the two flags whose fd-table detach is why rustix
    // marks this call unsafe, can never be set here.
    unsafe { rustix::thread::unshare_unsafe(flags) }
}

/// Hand-written Linux-PAM FFI (`pam`), R5 task 5 / decision D1.
///
/// This is a byte-exact port of the upstream cgo shim
/// `central_pam_authenticate` in
/// `internal/adapter/authority/helper/pam_linux.go`:
///
/// ```c
/// struct pam_conv conversation = { central_pam_conversation, &data };
/// int result = pam_start(service, username, &conversation, &pamh);
/// if (result == PAM_SUCCESS) result = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
/// if (pamh != NULL) pam_end(pamh, result);
/// ```
///
/// Upstream does **not** call `pam_acct_mgmt` — authentication is the
/// whole observable contract, so the declared surface is exactly the
/// three calls upstream makes plus the conversation callback. The
/// constants and `repr(C)` layouts below are the Linux-PAM ABI from
/// `<security/_pam_types.h>` and `<security/pam_appl.h>`.
pub(crate) mod pam_ffi {
    use std::ffi::{CStr, c_char, c_int, c_void};
    use std::ptr;

    /// `PAM_SUCCESS` — `<security/_pam_types.h>`.
    pub(crate) const PAM_SUCCESS: c_int = 0;
    /// `PAM_BUF_ERR` — `<security/_pam_types.h>`.
    const PAM_BUF_ERR: c_int = 5;
    /// `PAM_CONV_ERR` — `<security/_pam_types.h>`.
    const PAM_CONV_ERR: c_int = 19;
    /// `PAM_PROMPT_ECHO_OFF` — `<security/_pam_types.h>`; the only
    /// prompt style the conversation will ever answer with data.
    const PAM_PROMPT_ECHO_OFF: c_int = 1;
    /// `PAM_PROMPT_ECHO_ON` — `<security/_pam_types.h>`; declared so
    /// the tests can name the style the conversation must refuse.
    /// Never matched in the callback — echo-on falls into the
    /// fail-closed arm like every unknown style.
    #[allow(dead_code)]
    const PAM_PROMPT_ECHO_ON: c_int = 2;
    /// `PAM_ERROR_MSG` — `<security/_pam_types.h>`; tolerated (no
    /// data), as upstream tolerates it.
    const PAM_ERROR_MSG: c_int = 3;
    /// `PAM_TEXT_INFO` — `<security/_pam_types.h>`; tolerated (no
    /// data), as upstream tolerates it.
    const PAM_TEXT_INFO: c_int = 4;
    /// `PAM_DISALLOW_NULL_AUTHTOK` — `<security/_pam_types.h>`;
    /// upstream's `pam_authenticate` flag.
    const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;

    /// `struct pam_message` — `<security/_pam_types.h>`:
    /// `{ int msg_style; const char *msg; }`.
    #[repr(C)]
    pub(crate) struct PamMessage {
        msg_style: c_int,
        #[allow(dead_code)]
        msg: *const c_char,
    }

    /// `struct pam_response` — `<security/_pam_types.h>`:
    /// `{ char *resp; int resp_retcode; }`.
    #[repr(C)]
    struct PamResponse {
        resp: *mut c_char,
        #[allow(dead_code)]
        resp_retcode: c_int,
    }

    /// `struct pam_conv` — `<security/_pam_types.h>`:
    /// `{ int (*conv)(...); void *appdata_ptr; }`.
    #[repr(C)]
    struct PamConv {
        conv: Option<
            unsafe extern "C" fn(
                c_int,
                *const *const PamMessage,
                *mut *mut PamResponse,
                *mut c_void,
            ) -> c_int,
        >,
        appdata_ptr: *mut c_void,
    }

    /// `pam_handle_t` — opaque to callers (`<security/pam_appl.h>`
    /// only ever hands out `pam_handle_t*`).
    #[repr(C)]
    struct PamHandle {
        _private: [u8; 0],
    }

    // SAFETY: these declarations match `<security/pam_appl.h>` on
    // Linux-PAM byte-for-byte — argument types, return type, and the
    // out-pointer contract of `pam_start` — verified against the
    // reference host's headers for R5 task 5.
    unsafe extern "C" {
        /// `int pam_start(const char *service_name, const char *user,
        /// const struct pam_conv *pam_conversation, pam_handle_t **pamh);`
        fn pam_start(
            service_name: *const c_char,
            user: *const c_char,
            pam_conversation: *const PamConv,
            pamh: *mut *mut PamHandle,
        ) -> c_int;
        /// `int pam_authenticate(pam_handle_t *pamh, int flags);`
        fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
        /// `int pam_end(pam_handle_t *pamh, int pam_status);`
        fn pam_end(pamh: *mut PamHandle, pam_status: c_int) -> c_int;
    }

    /// `free_responses` — release a response array the conversation
    /// partially filled, freeing each `strdup`ed entry first. Upstream
    /// frees only the array and leaks the earlier copies; freeing the
    /// entries too is strictly tighter on a path that can only run on
    /// failure.
    ///
    /// `filled` is how many leading entries may hold a `strdup`ed
    /// pointer (entries are `calloc`ed, so the rest are NULL).
    ///
    /// # Safety
    /// `replies` must be a `libc::calloc` allocation of at least
    /// `filled` `PamResponse`s, or NULL.
    unsafe fn free_responses(replies: *mut PamResponse, filled: c_int) {
        if replies.is_null() {
            return;
        }
        for i in 0..filled {
            // SAFETY: `replies` is a live calloc allocation of at
            // least `filled` entries (the caller guarantees the
            // bound); `resp` entries are either NULL (calloc) or a
            // `libc::strdup` allocation, both safe to pass to
            // `libc::free`.
            let entry = unsafe { (*replies.add(i as usize)).resp };
            if !entry.is_null() {
                // SAFETY: `entry` is a live `strdup` allocation as
                // established above.
                unsafe { libc::free(entry.cast()) };
            }
        }
        // SAFETY: `replies` is the `calloc` allocation established
        // above.
        unsafe { libc::free(replies.cast()) };
    }

    /// `central_pam_conversation` — the conversation callback,
    /// byte-exact the upstream C:
    ///
    /// - `PAM_PROMPT_ECHO_OFF` → `strdup(password)` (the only style
    ///   ever answered with data);
    /// - `PAM_TEXT_INFO`, `PAM_ERROR_MSG` → tolerated, response entry
    ///   stays NULL — upstream explicitly admits both and so must we:
    ///   a real `common-auth` stack may surface informational lines,
    ///   and refusing them would deny legitimate authentications that
    ///   upstream accepts;
    /// - anything else (`PAM_PROMPT_ECHO_ON`, unknown `msg_style`) →
    ///   `PAM_CONV_ERR` — fail closed, no data ever leaves.
    ///
    /// # Safety
    /// Called only by libpam, on the thread inside `pam_authenticate`,
    /// with `appdata_ptr` being the `*const c_char` secret pointer
    /// [`authenticate`] installed in `PamConv` — a live NUL-terminated
    /// string that outlives the whole call.
    unsafe extern "C" fn conversation(
        num_msg: c_int,
        msg: *const *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata_ptr: *mut c_void,
    ) -> c_int {
        if num_msg < 0 || msg.is_null() || resp.is_null() || appdata_ptr.is_null() {
            return PAM_CONV_ERR;
        }
        let password = appdata_ptr.cast::<c_char>();
        // SAFETY: `calloc` returns a zeroed allocation of
        // `num_msg * size_of::<PamResponse>()` bytes or NULL; the NULL
        // case is checked. The allocation is handed to libpam below
        // (it frees `pam_response` arrays after the conversation) or
        // freed by `free_responses` on the error paths.
        let replies = unsafe { libc::calloc(num_msg as usize, size_of::<PamResponse>()) }
            .cast::<PamResponse>();
        if replies.is_null() {
            return PAM_CONV_ERR;
        }
        for i in 0..num_msg {
            // SAFETY: the libpam conversation contract passes `msg` as
            // a pointer to an array of `num_msg` pointers, each naming
            // a live `pam_message` for the duration of the call.
            let message = unsafe { *msg.add(i as usize) };
            if message.is_null() {
                // SAFETY: `replies` is our calloc allocation of
                // `num_msg` entries; `i` bounds the filled prefix.
                unsafe { free_responses(replies, i) };
                return PAM_CONV_ERR;
            }
            // SAFETY: `message` is a live `pam_message` per the
            // contract above.
            let style = unsafe { (*message).msg_style };
            if style == PAM_PROMPT_ECHO_OFF {
                // SAFETY: `password` is the NUL-terminated secret
                // `authenticate` installed; it outlives this call.
                // `strdup` allocates a copy libpam frees after use.
                let copy = unsafe { libc::strdup(password) };
                if copy.is_null() {
                    // SAFETY: as above — `i` bounds the filled prefix.
                    unsafe { free_responses(replies, i) };
                    return PAM_BUF_ERR;
                }
                // SAFETY: `replies` has `num_msg` entries and `i` is
                // in bounds.
                unsafe { (*replies.add(i as usize)).resp = copy };
            } else if style != PAM_TEXT_INFO && style != PAM_ERROR_MSG {
                // SAFETY: as above — `i` bounds the filled prefix.
                unsafe { free_responses(replies, i) };
                return PAM_CONV_ERR;
            }
        }
        // SAFETY: `resp` is the out-pointer libpam handed us, checked
        // non-NULL above; `replies` ownership passes to libpam here.
        unsafe { *resp = replies };
        PAM_SUCCESS
    }

    /// `central_pam_authenticate(service, userName, secret)` — the
    /// upstream C shim verbatim: `pam_start`, then
    /// `pam_authenticate(PAM_DISALLOW_NULL_AUTHTOK)` on success, then
    /// `pam_end` propagating the result as the final status. The raw
    /// PAM result code is returned for `sys::pam` to map onto the
    /// closed denial envelope — this function never maps anything to
    /// success except `PAM_SUCCESS` itself.
    pub(crate) fn authenticate(service: &CStr, user: &CStr, secret: &CStr) -> c_int {
        let conversation = PamConv {
            conv: Some(conversation),
            // The upstream shim passes `&data` where data wraps the
            // password pointer; passing the pointer itself is the same
            // contract with our own callback.
            appdata_ptr: secret.as_ptr().cast::<c_char>().cast_mut().cast::<c_void>(),
        };
        let mut pamh: *mut PamHandle = ptr::null_mut();
        // SAFETY: `service`/`user`/`secret` are live NUL-terminated
        // `CStr`s for the whole call; `&conversation` names a stack
        // struct that outlives `pam_authenticate` below — the only
        // call that can invoke the callback and dereference
        // `appdata_ptr`; `&mut pamh` is a valid out-pointer libpam
        // writes on success.
        let mut result =
            unsafe { pam_start(service.as_ptr(), user.as_ptr(), &conversation, &mut pamh) };
        if result == PAM_SUCCESS {
            // SAFETY: `pamh` is a live handle returned by the
            // successful `pam_start` above. `conversation` and the
            // secret its `appdata_ptr` names both outlive this call —
            // the only point the callback can run.
            result = unsafe { pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK) };
        }
        if !pamh.is_null() {
            // SAFETY: `pamh` came from `pam_start` and has not been
            // ended yet; upstream passes the result through as
            // `pam_status` verbatim, so a failed authentication is
            // recorded in the handle's closing status exactly as the
            // C shim records it.
            let _ = unsafe { pam_end(pamh, result) };
        }
        result
    }

    #[cfg(test)]
    mod tests {
        //! The conversation callback, exercised directly — the same
        //! `struct pam_message` array libpam would hand it. Every test
        //! frees the response array exactly as libpam would
        //! (`free(resp[i].resp)` per non-NULL entry, then `free(resp)`).

        use super::*;
        use std::ffi::CString;

        const PASSWORD: &CStr = c"s3cret-phrase";

        fn call_conversation(styles: &[c_int]) -> (c_int, *mut PamResponse) {
            let text = CString::new("prompt: ").unwrap();
            let messages: Vec<PamMessage> = styles
                .iter()
                .map(|&s| PamMessage {
                    msg_style: s,
                    msg: text.as_ptr(),
                })
                .collect();
            let ptrs: Vec<*const PamMessage> = messages.iter().map(|m| m as *const _).collect();
            let mut responses: *mut PamResponse = ptr::null_mut();
            // SAFETY: `ptrs` names a live array of `len` message
            // pointers, `text` outlives the call, `PASSWORD` is a live
            // NUL-terminated static, and `responses` is a valid
            // out-pointer — the same contract libpam holds the
            // callback to.
            let rc = unsafe {
                conversation(
                    c_int::try_from(styles.len()).unwrap(),
                    ptrs.as_ptr(),
                    &mut responses,
                    PASSWORD.as_ptr().cast_mut().cast::<c_void>(),
                )
            };
            (rc, responses)
        }

        /// Free a response array the way libpam would, so tests do not
        /// leak: release each non-NULL `resp` then the array.
        ///
        /// # Safety
        /// `responses` must be a `calloc`ed array of `count` entries
        /// returned by `call_conversation`, or NULL.
        unsafe fn free_all(responses: *mut PamResponse, count: usize) {
            unsafe { free_responses(responses, c_int::try_from(count).unwrap()) };
        }

        /// `PAM_PROMPT_ECHO_OFF` is the only prompt answered — and it
        /// is answered with a `strdup`ed copy of the secret.
        #[test]
        fn echo_off_prompt_is_answered_with_the_secret() {
            let (rc, responses) = call_conversation(&[PAM_PROMPT_ECHO_OFF]);
            assert_eq!(rc, PAM_SUCCESS);
            assert!(!responses.is_null());
            // SAFETY: one entry, calloc'd then filled by the callback.
            let answer = unsafe { (*responses).resp };
            assert!(!answer.is_null());
            // SAFETY: `answer` is the `strdup`ed copy just asserted
            // non-NULL.
            assert_eq!(unsafe { CStr::from_ptr(answer) }, PASSWORD);
            // SAFETY: the array came from call_conversation.
            unsafe { free_all(responses, 1) };
        }

        /// `PAM_PROMPT_ECHO_ON` is refused outright: no data leaves,
        /// the conversation fails — the fail-closed rule.
        #[test]
        fn echo_on_prompt_is_refused() {
            let (rc, responses) = call_conversation(&[PAM_PROMPT_ECHO_ON]);
            assert_eq!(rc, PAM_CONV_ERR);
            assert!(responses.is_null());
        }

        /// `PAM_TEXT_INFO` and `PAM_ERROR_MSG` are tolerated but carry
        /// no response data — upstream's exact contract: an
        /// informational line from a module must not fail a legitimate
        /// authentication, and must never be answered either.
        #[test]
        fn informational_messages_are_tolerated_without_data() {
            let (rc, responses) = call_conversation(&[PAM_TEXT_INFO, PAM_ERROR_MSG]);
            assert_eq!(rc, PAM_SUCCESS);
            assert!(!responses.is_null());
            for i in 0..2usize {
                // SAFETY: `responses` is a two-entry array.
                let entry = unsafe { (*responses.add(i)).resp };
                assert!(entry.is_null(), "informational message {i} got data");
            }
            // SAFETY: the array came from call_conversation.
            unsafe { free_all(responses, 2) };
        }

        /// An unknown `msg_style` fails closed, and a single bad
        /// message poisons the whole conversation even when earlier
        /// prompts were answerable.
        #[test]
        fn unknown_and_mixed_styles_fail_closed() {
            let (rc, responses) = call_conversation(&[99]);
            assert_eq!(rc, PAM_CONV_ERR);
            assert!(responses.is_null());

            let (rc, responses) = call_conversation(&[PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON]);
            assert_eq!(rc, PAM_CONV_ERR);
            assert!(responses.is_null());
        }

        /// The malformed-call cases: negative count and NULL pointers
        /// are conversation errors, never reads.
        #[test]
        fn malformed_calls_are_conversation_errors() {
            let mut responses: *mut PamResponse = ptr::null_mut();
            // SAFETY: deliberately malformed arguments — the callback
            // must refuse before touching them.
            let rc = unsafe { conversation(-1, ptr::null(), &mut responses, ptr::null_mut()) };
            assert_eq!(rc, PAM_CONV_ERR);
        }

        /// The whole `pam_start` → `pam_authenticate` → `pam_end`
        /// chain against the live libpam: a service that is not
        /// configured must never produce `PAM_SUCCESS` — authentication
        /// fails closed. Skips only if libpam itself is absent, which
        /// would have failed the link step, so this runs everywhere
        /// the crate builds.
        #[test]
        fn unconfigured_service_never_authenticates() {
            let service = CString::new("central-no-such-service-t5").unwrap();
            let user = CString::new("central-no-such-user-t5").unwrap();
            let secret = CString::new("wrong").unwrap();
            let result = authenticate(&service, &user, &secret);
            assert_ne!(
                result, PAM_SUCCESS,
                "an unconfigured PAM service produced PAM_SUCCESS"
            );
        }

        /// Struct layout pins — the FFI structs are the C ABI, not a
        /// Rust choice: a layout drift is a silent memory corruption
        /// in the conversation.
        #[test]
        fn pam_struct_layouts_match_the_c_abi() {
            assert_eq!(size_of::<PamMessage>(), 16);
            assert_eq!(size_of::<PamResponse>(), 16);
            assert_eq!(size_of::<PamConv>(), 16);
            assert_eq!(align_of::<PamMessage>(), align_of::<usize>());
            assert_eq!(align_of::<PamResponse>(), align_of::<usize>());
            assert_eq!(align_of::<PamConv>(), align_of::<usize>());
        }
    }
}
