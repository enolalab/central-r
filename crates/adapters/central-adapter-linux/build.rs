//! Build script — link the PAM authentication library (R5 task 5,
//! decision D1).
//!
//! Upstream links libpam through a cgo directive (`#cgo LDFLAGS:
//! -lpam`, `internal/adapter/authority/helper/pam_linux.go`); the Rust
//! port's hand-written FFI in `sys::audited` needs the same single
//! link flag, and nothing else — no wrapper crate, no generated
//! bindings.
//!
//! The flag makes `libpam` a hard prerequisite of building this crate,
//! exactly as the `linux && cgo && pam` build tag made it a
//! prerequisite of the upstream helper: the crate is the Linux
//! platform boundary and is built only on hosts that carry the PAM
//! development files (the R5 pinned reference host does).

fn main() {
    // `-lpam`, byte-for-byte the upstream cgo directive.
    println!("cargo:rustc-link-lib=pam");
}
