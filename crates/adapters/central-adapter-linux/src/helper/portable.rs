//! Portable bundle filesystem/crypto — upstream `internal/portable/
//! bundle.go`'s I/O half (`EncryptStream`, `DecryptStream`, `BuildTarGz`,
//! `ExtractTarGz`, `VerifyExtractedTree`, `LoadOrMintExportIdentity`,
//! `ScanProtectedSubset`) plus `import.go`'s `VerifyExtractedTree`. The
//! chunked AES-256-GCM framing is byte-compatible with upstream:
//! `BX1GCM01` + 12-byte base nonce, then per segment u32be length +
//! GCM-sealed chunk under nonce `base[..4] || BE64(index)`, no AAD.
//! The tar writer reproduces Go `archive/tar`'s PAX-format byte layout:
//! sorted `mtime=`/`path=` x-header records, USTAR-shaped header bodies
//! (truncated name, no 155-prefix split when PAX was emitted), octal
//! fields, Go checksum format.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use central_infra::portable as domain;
use central_infra::portable::{ExportManifest, ManifestFile};

/// One refusal — every caller maps it onto a stable wire reason; the
/// message is a locator-free diagnostic for helper logs.
#[derive(Debug)]
pub struct PortableError(pub String);

impl PortableError {
    fn msg(text: impl Into<String>) -> Self {
        Self(format!("portable: {}", text.into()))
    }
}

impl std::fmt::Display for PortableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PortableError {}

fn err<T>(text: impl Into<String>) -> Result<T, PortableError> {
    Err(PortableError::msg(text))
}

// ---------------------------------------------------------------------------
// Chunked AES-256-GCM — `EncryptStream` / `DecryptStream` / `segmentNonce`.
// ---------------------------------------------------------------------------

const GCM_TAG: usize = 16;
const BASE_NONCE_LEN: usize = 12;
const HEADER_LEN: usize = domain::CHUNKED_MAGIC.len() + BASE_NONCE_LEN;
const MAX_SEALED: usize = domain::CHUNK_SIZE + GCM_TAG;

fn segment_nonce(base: &[u8; BASE_NONCE_LEN], index: u64) -> Nonce<aes_gcm::aead::consts::U12> {
    let mut nonce = [0u8; BASE_NONCE_LEN];
    nonce[..4].copy_from_slice(&base[..4]);
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce.into()
}

/// `EncryptStream` — magic + random 12-byte base nonce, then per segment
/// u32be length + AES-256-GCM ciphertext. Segment `i` uses nonce
/// `base[..4] || BE64(i)`; domain separation is by construction.
pub fn encrypt_stream(
    mut plaintext: impl Read,
    mut w: impl Write,
    key: &[u8; 32],
) -> Result<(), PortableError> {
    let gcm = <Aes256Gcm as KeyInit>::new_from_slice(key)
        .map_err(|_| PortableError::msg("key init failed"))?;
    let mut base = [0u8; BASE_NONCE_LEN];
    rustix::rand::getrandom(&mut base, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| PortableError::msg("nonce source failed"))?;
    w.write_all(domain::CHUNKED_MAGIC)
        .and_then(|()| w.write_all(&base))
        .map_err(|e| PortableError::msg(format!("header write: {e}")))?;
    let mut buf = vec![0u8; domain::CHUNK_SIZE];
    let mut index: u64 = 0;
    loop {
        // Go uses io.ReadFull: n>0 with ErrUnexpectedEOF is still a
        // final short segment; a clean EOF ends the stream.
        let mut filled = 0usize;
        let mut eof = false;
        while filled < buf.len() {
            match plaintext.read(&mut buf[filled..]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => filled += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(PortableError::msg(format!("read: {e}"))),
            }
        }
        if filled > 0 {
            let sealed = gcm
                .encrypt(&segment_nonce(&base, index), Payload::from(&buf[..filled]))
                .map_err(|_| PortableError::msg("seal failed"))?;
            w.write_all(&(sealed.len() as u32).to_be_bytes())
                .and_then(|()| w.write_all(&sealed))
                .map_err(|e| PortableError::msg(format!("segment write: {e}")))?;
            index += 1;
        }
        if eof {
            return Ok(());
        }
    }
}

/// `DecryptStream` — inverts [`encrypt_stream`], verifying every segment
/// tag. Truncated, reordered, or tampered input fails; output written
/// before the failure is the caller's to discard.
pub fn decrypt_stream(
    mut ciphertext: impl Read,
    mut w: impl Write,
    key: &[u8; 32],
) -> Result<(), PortableError> {
    let gcm = <Aes256Gcm as KeyInit>::new_from_slice(key)
        .map_err(|_| PortableError::msg("key init failed"))?;
    let mut header = [0u8; HEADER_LEN];
    if read_full(&mut ciphertext, &mut header)? != Fill::Full {
        return err("bundle header: short read");
    }
    if header[..domain::CHUNKED_MAGIC.len()] != domain::CHUNKED_MAGIC[..] {
        return err("bundle magic mismatch");
    }
    let mut base = [0u8; BASE_NONCE_LEN];
    base.copy_from_slice(&header[domain::CHUNKED_MAGIC.len()..]);
    let mut index: u64 = 0;
    loop {
        let mut length = [0u8; 4];
        match read_full(&mut ciphertext, &mut length)? {
            // io.ReadFull: zero bytes read → io.EOF (clean end).
            Fill::Empty => return Ok(()),
            // A partial length prefix → ErrUnexpectedEOF ("bundle framing").
            Fill::Partial => return err("bundle framing: truncated length"),
            Fill::Full => {}
        }
        let size = u32::from_be_bytes(length) as usize;
        if size == 0 || size > MAX_SEALED {
            return err(format!("bundle segment size {size} out of range"));
        }
        let mut sealed = vec![0u8; size];
        if read_full(&mut ciphertext, &mut sealed)? != Fill::Full {
            return err("bundle truncated");
        }
        let opened = gcm
            .decrypt(&segment_nonce(&base, index), Payload::from(&sealed[..]))
            .map_err(|_| {
                PortableError::msg(format!("bundle authentication failed at segment {index}"))
            })?;
        w.write_all(&opened)
            .map_err(|e| PortableError::msg(format!("plain write: {e}")))?;
        index += 1;
    }
}

/// `io.ReadFull` fill outcomes — Go distinguishes `io.EOF` (0 bytes
/// read) from `io.ErrUnexpectedEOF` (partial); Rust's `read_exact`
/// conflates them, so the loop counts bytes itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fill {
    /// Buffer completely filled.
    Full,
    /// EOF before any byte — Go's `io.EOF`.
    Empty,
    /// EOF after a partial fill — Go's `io.ErrUnexpectedEOF`.
    Partial,
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> Result<Fill, PortableError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return Ok(if filled == 0 {
                    Fill::Empty
                } else {
                    Fill::Partial
                });
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(PortableError::msg(format!("read: {e}"))),
        }
    }
    Ok(Fill::Full)
}

// ---------------------------------------------------------------------------
// Deterministic tar — `BuildTarGz` (Go archive/tar PAX byte layout).
// ---------------------------------------------------------------------------

/// `fs.ValidPath` — no leading slash, no empty or dot segments.
pub fn valid_path(rel: &str) -> bool {
    if rel.is_empty() || rel.starts_with('/') {
        return false;
    }
    if rel == "." {
        return true;
    }
    !rel.split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
}

fn is_ascii(s: &str) -> bool {
    s.is_ascii()
}

/// `toASCII` — Go replaces each non-ASCII rune with '?' when falling
/// back to a truncated USTAR/PAX-body name.
fn to_ascii(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii() { c } else { '?' })
        .collect()
}

/// `splitUSTARPath` — prefix ≤155 bytes, suffix ≤100 bytes, split at the
/// last '/' that fits the prefix budget; both halves must fit.
fn split_ustar_path(name: &str) -> Option<(String, String)> {
    let bytes = name.as_bytes();
    if !is_ascii(name) {
        return None;
    }
    if bytes.len() <= 100 {
        return Some((String::new(), name.to_owned()));
    }
    // Go iterates every '/' position, keeping the last valid split.
    let mut best: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'/' && i <= 155 && bytes.len() - i - 1 <= 100 && bytes.len() - i - 1 > 0 {
            best = Some(i);
        }
    }
    let i = best?;
    Some((name[..i].to_owned(), name[i + 1..].to_owned()))
}

/// `formatPAXRecord` — `%d %s=%s\n` with the digit width iterated to a
/// fixpoint, exactly like Go.
fn format_pax_record(key: &str, value: &str) -> String {
    let mut n = key.len() + value.len() + 3;
    loop {
        let record = format!("{n} {key}={value}\n");
        if record.len() == n {
            return record;
        }
        n = record.len();
    }
}

/// `formatPAXTime` — `sec.frac` with the fraction trimmed of trailing
/// zeros; whole seconds emit no fraction.
fn format_pax_time(t: OffsetDateTime) -> String {
    let sec = t.unix_timestamp();
    let nsec = t.nanosecond();
    if nsec == 0 {
        return format!("{sec}");
    }
    let frac = format!("{nsec:09}");
    let frac = frac.trim_end_matches('0');
    format!("{sec}.{frac}")
}

fn octal_field(value: u64, digits: usize) -> Vec<u8> {
    let mut field = format!("{value:0>width$o}", width = digits).into_bytes();
    field.push(0);
    field
}

/// One 512-byte USTAR-shaped header block (Go's `v7Plus` template —
/// also what PAX entries use). `prefix` is empty for PAX entries.
#[allow(clippy::too_many_arguments)]
fn write_header_block(
    w: &mut impl Write,
    name: &str,
    prefix: &str,
    mode: u32,
    size: u64,
    mtime_secs: i64,
    typeflag: u8,
) -> std::io::Result<()> {
    // Go leaves devmajor/devminor as raw NULs on 'x'/'g' x-header
    // entries but formats "0000000\0" on the v7-plus file/dir template.
    let fill_dev = typeflag != b'x';
    let mut block = [0u8; 512];
    // name[0:100]
    let name_bytes = to_ascii(name).into_bytes();
    block[..name_bytes.len().min(100)].copy_from_slice(&name_bytes[..name_bytes.len().min(100)]);
    // mode[100:108] — "%07o\0"
    block[100..108].copy_from_slice(&octal_field(u64::from(mode), 7));
    // uid[108:116], gid[116:124] — zeroed identities.
    block[108..116].copy_from_slice(&octal_field(0, 7));
    block[116..124].copy_from_slice(&octal_field(0, 7));
    // size[124:136] — "%011o\0"
    block[124..136].copy_from_slice(&octal_field(size, 11));
    // mtime[136:148]
    block[136..148].copy_from_slice(&octal_field(mtime_secs.max(0) as u64, 11));
    // chksum[148:156] — spaces while summing.
    for b in &mut block[148..156] {
        *b = b' ';
    }
    // typeflag[156]
    block[156] = typeflag;
    // linkname[157:257] — empty.
    // magic[257:265] — "ustar\0" + "00"
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    // uname[265:297], gname[297:329] — empty.
    // devmajor[329:337], devminor[337:345].
    if fill_dev {
        block[329..337].copy_from_slice(&octal_field(0, 7));
        block[337..345].copy_from_slice(&octal_field(0, 7));
    }
    // prefix[345:500]
    let prefix_bytes = prefix.as_bytes();
    block[345..345 + prefix_bytes.len().min(155)]
        .copy_from_slice(&prefix_bytes[..prefix_bytes.len().min(155)]);
    // pad[500:512] stays zero.
    let sum: u64 = block.iter().map(|&b| u64::from(b)).sum();
    // Go's chksum format: "%06o\0 " (six digits, NUL, trailing space).
    let chksum = format!("{sum:06o}\0 ").into_bytes();
    block[148..156].copy_from_slice(&chksum);
    w.write_all(&block)
}

fn pad512(w: &mut impl Write, written: u64) -> std::io::Result<()> {
    let rem = (written % 512) as usize;
    if rem != 0 {
        w.write_all(&vec![0u8; 512 - rem])?;
    }
    Ok(())
}

/// `BuildTarGz` — sorted names, uid/gid 0, file 0600 / dir 0700, mtime
/// pinned to `created_at`. Symlinks and special files are refused.
/// Emits Go's PAX layout: an `mtime` x-header record (plus `path` when
/// the name can't be USTAR-encoded) whenever the pinned time carries
/// nanoseconds, else a split-capable USTAR entry.
pub fn build_tar_gz(
    src_dir: &Path,
    w: impl Write,
    created_at: OffsetDateTime,
) -> Result<(), PortableError> {
    let mut names: Vec<String> = Vec::new();
    let mut stack = vec![src_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| PortableError::msg(format!("walk: {e}")))? {
            let entry = entry.map_err(|e| PortableError::msg(format!("walk: {e}")))?;
            let ft = entry
                .file_type()
                .map_err(|e| PortableError::msg(format!("walk: {e}")))?;
            if ft.is_symlink() {
                return err(format!("refusing symlink {}", entry.path().display()));
            }
            if !ft.is_file() && !ft.is_dir() {
                return err(format!("refusing special file {}", entry.path().display()));
            }
            let rel = entry
                .path()
                .strip_prefix(src_dir)
                .map_err(|_| PortableError::msg("walk escape"))?
                .to_string_lossy()
                .replace('\\', "/");
            if !valid_path(&rel) {
                return err(format!("invalid path {rel}"));
            }
            names.push(rel);
            if ft.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    names.sort();
    let gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(w, flate2::Compression::default());
    let mut gz = gz;
    for name in &names {
        let full = src_dir.join(name);
        let meta = fs::symlink_metadata(&full)
            .map_err(|e| PortableError::msg(format!("lstat {name}: {e}")))?;
        let (typeflag, mode, size) = if meta.is_dir() {
            (b'5', 0o700u32, 0u64)
        } else {
            (b'0', 0o600u32, meta.len())
        };
        let mut records: Vec<(String, String)> = Vec::new();
        let prefer_pax = created_at.nanosecond() != 0;
        if prefer_pax {
            records.push(("mtime".to_owned(), format_pax_time(created_at)));
        }
        let ustar_split = split_ustar_path(name);
        // Go's verifyString: `path` records whenever the name is
        // non-ASCII or >100 bytes — independent of splittability.
        if !is_ascii(name) || name.len() > 100 {
            records.push(("path".to_owned(), name.clone()));
        }
        records.sort();
        let emit_pax = prefer_pax || ustar_split.is_none();
        if emit_pax {
            let record_bytes: String = records
                .iter()
                .map(|(k, v)| format_pax_record(k, v))
                .collect();
            let dir = name.rsplit_once('/').map(|(d, _)| d).unwrap_or(".");
            let base = name.rsplit('/').next().unwrap_or(name);
            let x_name = if dir == "." {
                format!("PaxHeaders.0/{base}")
            } else {
                format!("{dir}/PaxHeaders.0/{base}")
            };
            write_header_block(&mut gz, &x_name, "", 0, record_bytes.len() as u64, 0, b'x')
                .map_err(|e| PortableError::msg(format!("xheader: {e}")))?;
            gz.write_all(record_bytes.as_bytes())
                .and_then(|()| pad512(&mut gz, record_bytes.len() as u64))
                .map_err(|e| PortableError::msg(format!("xheader body: {e}")))?;
            // PAX body: name is the ASCII-truncated form — no split.
            let body_name = to_ascii(name);
            let truncated: String = {
                let b = body_name.as_bytes();
                String::from_utf8_lossy(&b[..b.len().min(100)]).into_owned()
            };
            write_header_block(
                &mut gz,
                &truncated,
                "",
                mode,
                size,
                created_at.unix_timestamp(),
                typeflag,
            )
            .map_err(|e| PortableError::msg(format!("header {name}: {e}")))?;
        } else if let Some((prefix, short)) = ustar_split {
            write_header_block(
                &mut gz,
                &short,
                &prefix,
                mode,
                size,
                created_at.unix_timestamp(),
                typeflag,
            )
            .map_err(|e| PortableError::msg(format!("header {name}: {e}")))?;
        }
        if !meta.is_dir() {
            let mut file = fs::File::open(&full)
                .map_err(|e| PortableError::msg(format!("open {name}: {e}")))?;
            let copied = std::io::copy(&mut file, &mut gz)
                .map_err(|e| PortableError::msg(format!("copy {name}: {e}")))?;
            pad512(&mut gz, copied).map_err(|e| PortableError::msg(format!("pad {name}: {e}")))?;
        }
    }
    gz.write_all(&[0u8; 1024])
        .map_err(|e| PortableError::msg(format!("trailer: {e}")))?;
    gz.finish()
        .map_err(|e| PortableError::msg(format!("gzip close: {e}")))?;
    Ok(())
}

/// `ExtractTarGz` — restores a `BuildTarGz` archive: absolute paths,
/// dot-dot, symlinks, hardlinks, devices, and mode/ownership escapes are
/// refused; entries land 0600/0700 under `dst`.
pub fn extract_tar_gz(r: impl Read, dst: &Path) -> Result<(), PortableError> {
    let gz = flate2::read::GzDecoder::new(r);
    let mut archive = tar::Archive::new(gz);
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);
    let dst_clean = dst.to_path_buf();
    let entries = archive
        .entries()
        .map_err(|e| PortableError::msg(format!("gzip: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| PortableError::msg(format!("tar: {e}")))?;
        let name = entry
            .path()
            .map_err(|e| PortableError::msg(format!("tar: {e}")))?
            .to_string_lossy()
            .replace('\\', "/");
        if !valid_path(&name) {
            return err(format!("refusing path {name:?}"));
        }
        let target = dst.join(&name);
        if !target.starts_with(&dst_clean) {
            return err(format!("refusing escape {name:?}"));
        }
        let ty = entry.header().entry_type();
        if ty == tar::EntryType::Directory {
            fs::create_dir_all(&target)
                .map_err(|e| PortableError::msg(format!("mkdir {name}: {e}")))?;
        } else if ty == tar::EntryType::Regular {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| PortableError::msg(format!("mkdir {name}: {e}")))?;
            }
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&target)
                .map_err(|e| PortableError::msg(format!("extract {name}: {e}")))?;
            let size = entry.header().size().unwrap_or(0);
            let mut limited = entry.take(size);
            std::io::copy(&mut limited, &mut out)
                .map_err(|e| PortableError::msg(format!("extract {name}: {e}")))?;
        } else {
            return err(format!("refusing entry type {name:?}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `VerifyExtractedTree` — manifest + complete-tree digest check.
// ---------------------------------------------------------------------------

/// `sha256.Sum256` of a file, streamed.
pub fn sha256_file(path: &Path) -> Result<String, PortableError> {
    let mut file = fs::File::open(path).map_err(|e| PortableError::msg(format!("hash: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| PortableError::msg(format!("hash: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(domain::hex_encode(&hasher.finalize()))
}

/// `sha256.Sum256` of bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    domain::hex_encode(&Sha256::digest(bytes))
}

/// `VerifyExtractedTree` — manifest present + complete tree: every
/// listed file exists with exact size and SHA-256, no unlisted files,
/// no duplicate or invalid paths. Returns the parsed manifest.
pub fn verify_extracted_tree(payload_dir: &Path) -> Result<ExportManifest, PortableError> {
    let raw = fs::read(payload_dir.join("manifest.json"))
        .map_err(|e| PortableError::msg(format!("manifest missing: {e}")))?;
    let manifest: ExportManifest = serde_json::from_slice(&raw)
        .map_err(|e| PortableError::msg(format!("manifest corrupt: {e}")))?;
    if manifest.bundle_id.is_empty()
        || manifest.instance_id.is_empty()
        || manifest.purpose.is_empty()
        || manifest.created_at.is_empty()
    {
        return err("manifest incomplete");
    }
    let mut listed: std::collections::HashMap<&str, &ManifestFile> =
        std::collections::HashMap::with_capacity(manifest.files.len());
    for file in &manifest.files {
        if file.path.is_empty() || file.path == "manifest.json" || !valid_path(&file.path) {
            return err(format!("manifest lists invalid path {:?}", file.path));
        }
        if listed.insert(&file.path, file).is_some() {
            return err(format!("manifest lists {:?} twice", file.path));
        }
    }
    let mut seen: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(listed.len());
    let mut stack = vec![payload_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| PortableError::msg(format!("walk: {e}")))? {
            let entry = entry.map_err(|e| PortableError::msg(format!("walk: {e}")))?;
            let ft = entry
                .file_type()
                .map_err(|e| PortableError::msg(format!("walk: {e}")))?;
            if ft.is_dir() {
                stack.push(entry.path());
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(payload_dir)
                .map_err(|_| PortableError::msg("walk escape"))?
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "manifest.json" {
                continue;
            }
            let want = listed
                .get(rel.as_str())
                .ok_or_else(|| PortableError::msg(format!("unlisted file {rel:?}")))?;
            let meta = entry
                .metadata()
                .map_err(|e| PortableError::msg(format!("stat {rel}: {e}")))?;
            if meta.len() as i64 != want.size {
                return err(format!(
                    "{rel} size {}, manifest says {}",
                    meta.len(),
                    want.size
                ));
            }
            let sum = sha256_file(&entry.path())?;
            if sum != want.sha256 {
                return err(format!("{rel} digest mismatch"));
            }
            seen.insert(rel);
        }
    }
    let mut missing: Vec<&str> = listed
        .keys()
        .filter(|p| !seen.contains(**p))
        .copied()
        .collect();
    if !missing.is_empty() {
        missing.sort();
        return err(format!("manifest files missing: {}", missing.join(", ")));
    }
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// `LoadOrMintExportIdentity` + `ScanProtectedSubset`.
// ---------------------------------------------------------------------------

/// `ExportIdentity` — the instance's persistent export keypair; minted
/// once on first export and lives instance-UID-only under the state
/// root. Wiping the instance destroys it — a new instance is a new
/// export identity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportIdentity {
    /// Lowercase hex Ed25519 seed.
    pub private_seed_hex: String,
    /// Lowercase hex Ed25519 verifying key.
    pub public_key_hex: String,
    /// RFC 3339(nano) mint timestamp.
    pub created_at: String,
}

/// `LoadOrMintExportIdentity` — loads the identity or creates it exactly
/// once (O_EXCL: a concurrent first export loads what won). A
/// present-but-malformed file refuses rather than re-minting — silent
/// re-minting would orphan every token the old key signed. Returns
/// `(identity, created)`.
pub fn load_or_mint_export_identity(
    path: &Path,
    uid: u32,
    gid: u32,
    now: OffsetDateTime,
) -> Result<(ExportIdentity, bool), PortableError> {
    match fs::read(path) {
        Ok(raw) => {
            let identity: ExportIdentity = serde_json::from_slice(&raw)
                .map_err(|e| PortableError::msg(format!("export identity corrupt: {e}")))?;
            let seed = domain::hex_decode(&identity.private_seed_hex)
                .ok_or_else(|| PortableError::msg("export identity corrupt"))?;
            if seed.len() != 32 {
                return err("export identity corrupt");
            }
            let mut seed_arr = [0u8; 32];
            seed_arr.copy_from_slice(&seed);
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
            if domain::hex_encode(&signing.verifying_key().to_bytes())
                != identity.public_key_hex.to_lowercase()
            {
                return err("export identity corrupt");
            }
            return Ok((identity, false));
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(PortableError::msg(format!("identity read: {e}")));
        }
        _ => {}
    }
    let mut seed = [0u8; 32];
    rustix::rand::getrandom(&mut seed, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| PortableError::msg("seed source failed"))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let identity = ExportIdentity {
        private_seed_hex: domain::hex_encode(&seed),
        public_key_hex: domain::hex_encode(&signing.verifying_key().to_bytes()),
        created_at: domain::format_rfc3339_nano(now),
    };
    let encoded = serde_json::to_vec(&identity)
        .map_err(|e| PortableError::msg(format!("identity encode: {e}")))?;
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Go's `os.IsExist` → the concurrent minter won; load it.
            return load_or_mint_export_identity(path, uid, gid, now);
        }
        Err(e) => return Err(PortableError::msg(format!("identity write: {e}"))),
    };
    file.write_all(&encoded)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|e| PortableError::msg(format!("identity write: {e}")))?;
    drop(file);
    rustix::fs::chmod(path, rustix::fs::Mode::from_raw_mode(0o600))
        .map_err(|e| PortableError::msg(format!("identity chmod: {e}")))?;
    rustix::fs::chown(
        path,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    )
    .map_err(|e| PortableError::msg(format!("identity chown: {e}")))?;
    Ok((identity, true))
}

/// `ScanProtectedSubset` — refuses trust material in the staged
/// protected-state copy: denylisted names and secret markers in content.
pub fn scan_protected_subset(root: &Path) -> Result<(), PortableError> {
    const DENIED_NAMES: &[&str] = &[
        "export-identity.json",
        "tls-authority.json",
        "ceremony-mode",
        "grants",
        ".key",
        "passfile",
        ".pem",
    ];
    const DENIED_CONTENT: &[&str] = &["PRIVATE KEY", "ca_key", "leaf_key", "private_seed_hex"];
    let mut first: Option<PortableError> = None;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| PortableError::msg(format!("walk: {e}")))? {
            let entry = entry.map_err(|e| PortableError::msg(format!("walk: {e}")))?;
            let base = entry.file_name().to_string_lossy().to_lowercase();
            if DENIED_NAMES.iter().any(|d| base.contains(d)) {
                first.get_or_insert_with(|| {
                    PortableError::msg(format!(
                        "protected subset carries trust file {}",
                        entry.path().display()
                    ))
                });
                continue;
            }
            let ft = entry
                .file_type()
                .map_err(|e| PortableError::msg(format!("walk: {e}")))?;
            if ft.is_dir() {
                stack.push(entry.path());
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let raw =
                fs::read(entry.path()).map_err(|e| PortableError::msg(format!("scan: {e}")))?;
            if DENIED_CONTENT
                .iter()
                .any(|m| raw.windows(m.len()).any(|w| w == m.as_bytes()))
            {
                first.get_or_insert_with(|| {
                    PortableError::msg(format!(
                        "protected subset file {} carries secret marker",
                        entry.path().display()
                    ))
                });
            }
        }
    }
    match first {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use time::macros::datetime;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-portable-test-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("tmp");
        dir
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = domain::derive_bundle_key(&[0x42; 32]).unwrap_or_default();
        let plain: Vec<u8> = (0..(domain::CHUNK_SIZE * 2 + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        let mut sealed = Vec::new();
        encrypt_stream(&plain[..], &mut sealed, &key).expect("enc");
        let mut opened = Vec::new();
        decrypt_stream(&sealed[..], &mut opened, &key).expect("dec");
        assert_eq!(opened, plain);
    }

    #[test]
    fn decrypt_rejects_tamper_truncation_wrong_key_garbage() {
        let key = domain::derive_bundle_key(&[0x42; 32]).unwrap_or_default();
        let wrong = domain::derive_bundle_key(&[0x43; 32]).unwrap_or_default();
        let plain = vec![0xabu8; 700_000];
        let mut sealed = Vec::new();
        encrypt_stream(&plain[..], &mut sealed, &key).expect("enc");
        // Tampered ciphertext byte.
        let mut bad = sealed.clone();
        let n = bad.len();
        bad[n - 20] ^= 0x01;
        assert!(decrypt_stream(&bad[..], &mut Vec::new(), &key).is_err());
        // Truncated stream.
        assert!(decrypt_stream(&sealed[..sealed.len() - 3], &mut Vec::new(), &key).is_err());
        // Truncated mid-header.
        assert!(decrypt_stream(&sealed[..10], &mut Vec::new(), &key).is_err());
        // Wrong key.
        assert!(decrypt_stream(&sealed[..], &mut Vec::new(), &wrong).is_err());
        // Trailing garbage ≥ 4 bytes → out-of-range/framing refusal.
        let mut extra = sealed.clone();
        extra.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        assert!(decrypt_stream(&extra[..], &mut Vec::new(), &key).is_err());
        let mut extra = sealed;
        extra.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0xaa]);
        assert!(decrypt_stream(&extra[..], &mut Vec::new(), &key).is_err());
        // Bad magic.
        let mut bad = {
            let mut s = Vec::new();
            encrypt_stream(&plain[..], &mut s, &key).expect("enc");
            s
        };
        bad[0] = b'X';
        assert!(decrypt_stream(&bad[..], &mut Vec::new(), &key).is_err());
    }

    #[test]
    fn build_extract_tar_gz_deterministic_round_trip() {
        let src = tmp("tarsrc");
        fs::create_dir_all(src.join("backup/bodies")).expect("mkdir");
        fs::write(src.join("manifest.json"), b"{}\n").expect("w");
        fs::write(src.join("backup/binding.json"), b"{\"a\":1}\n").expect("w");
        fs::write(src.join("backup/bodies/b1.bin"), vec![7u8; 1000]).expect("w");
        let at = datetime!(2025-03-04 05:06:07.123456789 UTC);
        let mut a = Vec::new();
        build_tar_gz(&src, &mut a, at).expect("tar");
        let mut b = Vec::new();
        build_tar_gz(&src, &mut b, at).expect("tar");
        assert_eq!(a, b, "archive must be deterministic");
        let dst = tmp("tardst");
        extract_tar_gz(&a[..], &dst).expect("untar");
        assert_eq!(
            fs::read(dst.join("backup/binding.json")).unwrap_or_default(),
            b"{\"a\":1}\n"
        );
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &fs::metadata(dst.join("backup/bodies/b1.bin"))
                .expect("m")
                .permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        let _ = fs::remove_dir_all(&src);
        let _ = fs::remove_dir_all(&dst);
    }

    /// Env-gated fixture dump for the Go byte-parity check:
    /// `DUMP_SRC` + `DUMP_OUT` set → emit the same archive upstream's
    /// `BuildTarGz` produced and compare decompressed bytes.
    #[test]
    fn dump_archive_for_parity_check() {
        let (Ok(src), Ok(out)) = (std::env::var("DUMP_SRC"), std::env::var("DUMP_OUT")) else {
            return;
        };
        let at = std::env::var("DUMP_AT")
            .ok()
            .and_then(|s| domain::parse_rfc3339(&s))
            .unwrap_or(datetime!(2025-03-04 05:06:07.123456789 UTC));
        let mut buf = Vec::new();
        build_tar_gz(Path::new(&src), &mut buf, at).expect("tar");
        fs::write(&out, &buf).expect("dump");
    }

    #[test]
    fn build_tar_gz_refuses_symlink() {
        let src = tmp("tarsym");
        fs::write(src.join("real.txt"), b"x").expect("w");
        std::os::unix::fs::symlink(src.join("real.txt"), src.join("link.txt")).expect("ln");
        let mut out = Vec::new();
        assert!(build_tar_gz(&src, &mut out, datetime!(2025-01-01 00:00:00 UTC)).is_err());
        let _ = fs::remove_dir_all(&src);
    }

    #[test]
    fn verify_extracted_tree_contract() {
        let dir = tmp("tree");
        let body = b"payload-bytes";
        let sum = sha256_hex(body);
        fs::create_dir_all(dir.join("backup")).expect("m");
        fs::write(dir.join("backup/dump"), body).expect("w");
        let manifest = ExportManifest {
            bundle_id: "b".into(),
            instance_id: "i".into(),
            created_at: "t".into(),
            purpose: "p".into(),
            files: vec![ManifestFile {
                path: "backup/dump".into(),
                size: body.len() as i64,
                sha256: sum.clone(),
            }],
            body_count: 0,
        };
        let raw = serde_json::to_vec(&manifest).unwrap_or_default();
        fs::write(dir.join("manifest.json"), &raw).expect("w");
        let got = verify_extracted_tree(&dir).expect("verify");
        assert_eq!(got, manifest);
        // Unlisted file refuses.
        fs::write(dir.join("extra"), b"x").expect("w");
        assert!(verify_extracted_tree(&dir).is_err());
        fs::remove_file(dir.join("extra")).expect("rm");
        // Digest drift refuses.
        fs::write(dir.join("backup/dump"), b"different!!").expect("w");
        assert!(verify_extracted_tree(&dir).is_err());
        // Missing listed file refuses.
        fs::remove_file(dir.join("backup/dump")).expect("rm");
        assert!(verify_extracted_tree(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_mint_load_corrupt() {
        let dir = tmp("ident");
        let path = dir.join("export-identity.json");
        let now = datetime!(2025-01-02 03:04:05 UTC);
        // Same-uid chown succeeds unprivileged; production passes the
        // instance uid/gid (helper runs privileged).
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let (minted, created) = load_or_mint_export_identity(&path, uid, gid, now).expect("mint");
        assert!(created);
        let (loaded, created2) = load_or_mint_export_identity(&path, uid, gid, now).expect("load");
        assert!(!created2);
        assert_eq!(loaded.private_seed_hex, minted.private_seed_hex);
        fs::write(&path, b"not json").expect("w");
        assert!(load_or_mint_export_identity(&path, uid, gid, now).is_err());
        // Wrong public key for a valid seed refuses too.
        let mut bad = minted.clone();
        bad.public_key_hex = domain::hex_encode(&[0xee; 32]);
        fs::write(&path, serde_json::to_vec(&bad).unwrap_or_default()).expect("w");
        assert!(load_or_mint_export_identity(&path, uid, gid, now).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_protected_subset_flags_trust_material() {
        let dir = tmp("scan");
        fs::write(dir.join("config.json"), b"{}").expect("w");
        assert!(scan_protected_subset(&dir).is_ok());
        fs::write(dir.join("tls-authority.json"), b"{}").expect("w");
        assert!(scan_protected_subset(&dir).is_err());
        fs::remove_file(dir.join("tls-authority.json")).expect("rm");
        fs::write(dir.join("notes.txt"), b"has ca_key inside").expect("w");
        assert!(scan_protected_subset(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
