//! `runtime_connection_linux.go`'s `connectRoleFromPassfileValue` +
//! `OpenMigrationConnectionFromSealedPassfile` — the dedicated
//! `central-migrate` operator's closed pgpass parse and its fixed
//! `central_migration` role connect.
//!
//! The descriptor half (CLOEXEC/regular-file/tmpfs/size shape, the
//! upstream `validateMigrationPassfileDescriptor`) lives in
//! `central_adapter_linux::sys::memfd::read_migration_passfile` —
//! this module never sees the raw descriptor, only the bounded,
//! NUL-free bytes it returned. The caller owns zeroization.

use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::{ConnectOptions as _, PgConnection};

use central_foundation::failure::Failure;

use super::Result;

/// `maximumBackupPassfileBytes` — the broker-side pgpass value bound.
pub const MAXIMUM_BACKUP_PASSFILE_BYTES: usize = 64 * 1024;

/// `ErrBackupRuntimeConnection` — every refusal in this module maps
/// to the one typed connection failure; the credential material never
/// reaches an error message.
fn runtime_connection() -> Failure {
    Failure::unavailable(
        "backup_runtime_connection",
        "runtime connection is unavailable",
    )
}

/// One parsed libpq pgpass entry — `pgpassfile.Entry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgPassEntry {
    /// Hostname field.
    pub hostname: String,
    /// Port field.
    pub port: String,
    /// Database field.
    pub database: String,
    /// Username field.
    pub username: String,
    /// Password field.
    pub password: String,
}

/// `pgpassfile.ParsePassfile` — the libpq format: `#` comment and
/// blank lines skipped; fields separated by unescaped `:`; `\`
/// escapes `:` and `\`. `None` on malformed input or when the value
/// does not decode to exactly one entry — the upstream
/// `len(parsed.Entries) != 1` refusal.
pub fn parse_passfile(value: &[u8]) -> Option<PgPassEntry> {
    let text = std::str::from_utf8(value).ok()?;
    let mut entries = Vec::new();
    for raw_line in text.split('\n') {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = Vec::with_capacity(5);
        let mut field = String::new();
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                field.push(chars.next()?);
            } else if c == ':' {
                fields.push(std::mem::take(&mut field));
            } else {
                field.push(c);
            }
        }
        fields.push(field);
        if fields.len() != 5 {
            return None;
        }
        let mut fields = fields.into_iter();
        entries.push(PgPassEntry {
            hostname: fields.next()?,
            port: fields.next()?,
            database: fields.next()?,
            username: fields.next()?,
            password: fields.next()?,
        });
    }
    if entries.len() != 1 {
        return None;
    }
    entries.pop()
}

/// `connectRoleFromPassfileValue` — the closed parse plus the
/// non-caller-selectable `127.0.0.1:55432/central` connect for `role`
/// (`"central_migration"` for the operator). Password length is
/// bounded by [`MAXIMUM_BACKUP_PASSFILE_BYTES`].
///
/// # Errors
/// `backup_runtime_connection` on any parse/binding/connect failure.
async fn connect_role_from_passfile_value(
    value: &[u8],
    role: &str,
    application_name: &str,
) -> Result<PgConnection> {
    let Some(entry) = parse_passfile(value) else {
        return Err(runtime_connection());
    };
    if entry.hostname != "127.0.0.1"
        || entry.port != "55432"
        || entry.database != "central"
        || entry.username != role
        || entry.password.is_empty()
        || entry.password.len() > MAXIMUM_BACKUP_PASSFILE_BYTES
    {
        return Err(runtime_connection());
    }
    let mut options = PgConnectOptions::new()
        .host("127.0.0.1")
        .port(55432)
        .database("central")
        .username(role)
        .password(&entry.password)
        .ssl_mode(PgSslMode::Disable)
        .application_name(application_name);
    options = options.options([
        ("statement_timeout", "30000"),
        ("lock_timeout", "30000"),
        ("idle_in_transaction_session_timeout", "60000"),
    ]);
    options.connect().await.map_err(|_| runtime_connection())
}

/// `OpenMigrationConnectionFromSealedPassfile` (post-validation half)
/// — connect the fixed `central_migration` role with the
/// `central-migrate` application name from the bounded pgpass bytes
/// the caller already read off the validated B05 descriptor.
///
/// # Errors
/// `backup_runtime_connection` on any parse/binding/connect failure.
pub async fn open_migration_connection(value: &[u8]) -> Result<PgConnection> {
    connect_role_from_passfile_value(value, "central_migration", "central-migrate").await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ParsePassfile` — one clean entry, escapes, comment + blank
    /// lines skipped, and every malformed shape refusing.
    #[test]
    fn parse_passfile_accepts_exactly_one_entry() {
        let entry = parse_passfile(b"127.0.0.1:55432:central:central_migration:s3cret\n")
            .expect("one entry");
        assert_eq!(entry.hostname, "127.0.0.1");
        assert_eq!(entry.password, "s3cret");

        // `\:` and `\\` escapes decode inside fields.
        let escaped = parse_passfile(b"h\\:ost:55432:db:user:p\\\\ss\n").expect("escaped");
        assert_eq!(escaped.hostname, "h:ost");
        assert_eq!(escaped.password, "p\\ss");

        // Comments and blank lines carry no entry.
        let commented =
            parse_passfile(b"# comment\n\n127.0.0.1:55432:central:central_migration:x\n")
                .expect("comment skipped");
        assert_eq!(commented.username, "central_migration");
    }

    #[test]
    fn parse_passfile_refuses_wrong_shape() {
        for bad in [
            b"".as_slice(),
            b"\n".as_slice(),
            b"only:four:fields:x\n".as_slice(),
            b"a:b:c:d:e:f\n".as_slice(),
            b"1:2:3:4:5\n6:7:8:9:0\n".as_slice(),
            b"127.0.0.1:55432:central:central_migration:trailing\\".as_slice(),
            b"\xff\xfe:x:y:z:w\n".as_slice(),
        ] {
            assert!(parse_passfile(bad).is_none(), "{bad:?} must not parse");
        }
    }
}
