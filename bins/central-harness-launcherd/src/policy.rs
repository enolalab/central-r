//! Configuration (decision 6a), operator identity (decision 7), argv
//! grammar (decision 10), env rules (decision 11) and workdir checks —
//! upstream `policy.c`. Config values are kept as raw bytes: the C code
//! treats them as C strings, and only the grammar/env rules inspect
//! them byte-wise.

use std::ffi::OsStr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use central_adapter_harness::launcher::protocol::Reason;
use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, open};
use rustix::io::Errno;

use crate::knobs;
use crate::sys;

pub const CONFIG_PATH: &str = "/etc/central/harness-launcher.conf";
pub const LOGIN_DEFS_PATH: &str = "/etc/login.defs";
const CONFIG_MAX_BYTES: usize = 65536;
const DEFAULT_PIDS_MAX: i64 = 512;
const DEFAULT_MEMORY_MAX: i64 = 2 * 1024 * 1024 * 1024;
const PATH_MAX_LEN: usize = 4096;
const MAX_NAME: usize = 64; // CHL_MAX_NAME — token must be shorter
pub const MAX_HARNESSES: usize = 8;
pub const MAX_MOUNTS: usize = 16;
pub const MAX_HARNESS: usize = 32; // CHL_MAX_HARNESS

const RESOLVE_STRICT: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
const RESOLVE_NO_SYMLINKS: ResolveFlags =
    ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_MAGICLINKS);

#[derive(Clone, Default)]
pub struct Mount {
    pub harness: Vec<u8>,
    pub source: Vec<u8>,
    pub target: Vec<u8>,
    pub read_only: bool,
    pub is_dir: bool,
}

#[derive(Clone, Default)]
pub struct HarnessEntry {
    pub id: Vec<u8>,
    pub program: Vec<u8>,
    pub home_dir: Vec<u8>,
    pub has_home_dir: bool,
}

#[derive(Clone, Default)]
pub struct Config {
    pub operator_user: Vec<u8>,
    pub runtime_user: Vec<u8>,
    pub worktree_root: Vec<u8>,
    pub harnesses: Vec<HarnessEntry>,
    pub mounts: Vec<Mount>,
    pub pids_max: i64,
    pub memory_max: i64,
    pub cpu_max: Vec<u8>,
}

#[derive(Clone, Default)]
pub struct Operator {
    pub uid: u32,
    pub gid: u32,
    pub name: Vec<u8>,
    pub home: Vec<u8>,
}

/// Upstream `ARGV_REFUSED/ARGV_PROBE/ARGV_SESSION`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ArgvKind {
    Refused,
    Probe,
    Session,
}

/* ---- paths ---- */

/// Upstream `valid_components`: each `/`-separated piece is non-empty,
/// not `.`/`..`, and free of control characters; no trailing slash.
fn valid_components(path: &[u8]) -> bool {
    let mut i = 0;
    while i < path.len() {
        let end = path[i..].iter().position(|b| *b == b'/').map(|p| i + p);
        let len = end.unwrap_or(path.len()) - i;
        if len == 0 {
            return false;
        }
        if len == 1 && path[i] == b'.' {
            return false;
        }
        if len == 2 && path[i] == b'.' && path[i + 1] == b'.' {
            return false;
        }
        for &c in &path[i..i + len] {
            if c < 0x20 || c == 0x7f {
                return false;
            }
        }
        let Some(e) = end else { break };
        i = e + 1;
        if i == path.len() {
            return false; // trailing slash
        }
    }
    true
}

/// `chl_canonical_absolute`.
pub fn canonical_absolute(path: &[u8]) -> bool {
    path.len() > 1 && path.len() < PATH_MAX_LEN && path[0] == b'/' && valid_components(&path[1..])
}

/// `chl_canonical_relative`.
pub fn canonical_relative(path: &[u8]) -> bool {
    !path.is_empty() && path.len() < PATH_MAX_LEN && path[0] != b'/' && valid_components(path)
}

/// `chl_path_beneath` — strictly beneath.
pub fn path_beneath(root: &[u8], path: &[u8]) -> bool {
    path.len() > root.len() + 1 && path[..root.len()] == *root && path[root.len()] == b'/'
}

fn same_or_beneath(root: &[u8], path: &[u8]) -> bool {
    root == path || path_beneath(root, path)
}

/* ---- configuration file ---- */

fn config_path() -> Vec<u8> {
    if let Some(p) = knobs::config_path() {
        return p.as_bytes().to_vec();
    }
    CONFIG_PATH.as_bytes().to_vec()
}

fn config_owner_uid() -> u32 {
    if let Some(uid) = knobs::config_owner_uid() {
        return uid;
    }
    #[cfg(feature = "test-build")]
    {
        rustix::process::getuid().as_raw()
    }
    #[cfg(not(feature = "test-build"))]
    {
        0
    }
}

fn config_owner_gid() -> u32 {
    #[cfg(feature = "test-build")]
    {
        rustix::process::getgid().as_raw()
    }
    #[cfg(not(feature = "test-build"))]
    {
        0
    }
}

/// `tree_owner_uid` — root in production; the test's own uid in test
/// builds unless `CHL_TEST_TREE_OWNER_UID` names another.
fn tree_owner_uid() -> u32 {
    #[cfg(feature = "test-build")]
    {
        if let Some(uid) = knobs::tree_owner_uid() {
            return uid;
        }
        rustix::process::getuid().as_raw()
    }
    #[cfg(not(feature = "test-build"))]
    {
        0
    }
}

fn valid_user_name(s: &[u8]) -> bool {
    if s.is_empty() || s.len() >= 33 || s[0] == b'-' {
        return false;
    }
    s.iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-' || *c == b'.')
}

fn parse_number(s: &[u8], min: i64, max: i64) -> Option<i64> {
    if s.is_empty() || !s[0].is_ascii_digit() || !s.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let v: i64 = std::str::from_utf8(s).ok()?.parse().ok()?;
    (v >= min && v <= max).then_some(v)
}

/// `valid_harness_id` — 1..=32 of [a-z0-9-].
fn valid_harness_id(id: &[u8]) -> bool {
    !id.is_empty()
        && id.len() <= MAX_HARNESS
        && id
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn token<const N: usize>(src: &[u8]) -> Option<Vec<u8>> {
    (src.len() < N).then(|| src.to_vec())
}

struct PendingHome {
    id: Vec<u8>,
    path: Vec<u8>,
}

fn parse_line(c: &mut Config, tok: &[&[u8]], seen: &mut u32, homes: &mut Vec<PendingHome>) -> bool {
    const S_OPERATOR: u32 = 1;
    const S_RUNTIME: u32 = 2;
    const S_ROOT: u32 = 4;
    const S_PIDS: u32 = 8;
    const S_MEMORY: u32 = 16;
    const S_CPU: u32 = 32;
    macro_rules! once {
        ($bit:expr) => {
            if *seen & $bit != 0 {
                return false;
            }
            *seen |= $bit;
        };
    }
    let key = tok[0];
    if key == b"operator_user" && tok.len() == 2 {
        once!(S_OPERATOR);
        return valid_user_name(tok[1])
            && token::<MAX_NAME>(tok[1]).is_some_and(|t| {
                c.operator_user = t;
                true
            });
    }
    if key == b"runtime_user" && tok.len() == 2 {
        once!(S_RUNTIME);
        return valid_user_name(tok[1])
            && token::<MAX_NAME>(tok[1]).is_some_and(|t| {
                c.runtime_user = t;
                true
            });
    }
    if key == b"worktree_root" && tok.len() == 2 {
        once!(S_ROOT);
        return canonical_absolute(tok[1])
            && token::<PATH_MAX_LEN>(tok[1]).is_some_and(|t| {
                c.worktree_root = t;
                true
            });
    }
    if key == b"harness" && tok.len() == 3 {
        if !valid_harness_id(tok[1]) || !harness_has_grammar(tok[1]) || !canonical_absolute(tok[2])
        {
            return false;
        }
        if find_harness(c, tok[1]).is_some() || c.harnesses.len() == MAX_HARNESSES {
            return false;
        }
        let (id, program) = (token::<33>(tok[1]), token::<PATH_MAX_LEN>(tok[2]));
        match (id, program) {
            (Some(id), Some(program)) => {
                c.harnesses.push(HarnessEntry {
                    id,
                    program,
                    ..HarnessEntry::default()
                });
                true
            }
            _ => false,
        }
    } else if key == b"home_dir" && tok.len() == 3 {
        if !valid_harness_id(tok[1]) || !canonical_relative(tok[2]) || homes.len() == MAX_HARNESSES
        {
            return false;
        }
        if homes.iter().any(|h| h.id == tok[1]) {
            return false;
        }
        match (token::<33>(tok[1]), token::<PATH_MAX_LEN>(tok[2])) {
            (Some(id), Some(path)) => {
                homes.push(PendingHome { id, path });
                true
            }
            _ => false,
        }
    } else if key == b"mount" && tok.len() == 6 {
        if !valid_harness_id(tok[1]) || !canonical_relative(tok[2]) || !canonical_relative(tok[3]) {
            return false;
        }
        let (ro, rw) = (tok[4] == b"ro", tok[4] == b"rw");
        let (dir, file) = (tok[5] == b"dir", tok[5] == b"file");
        if !(ro || rw) || !(dir || file) || c.mounts.len() == MAX_MOUNTS {
            return false;
        }
        if c.mounts
            .iter()
            .any(|m| m.harness == tok[1] && m.target == tok[3])
        {
            return false;
        }
        match (
            token::<33>(tok[1]),
            token::<PATH_MAX_LEN>(tok[2]),
            token::<PATH_MAX_LEN>(tok[3]),
        ) {
            (Some(harness), Some(source), Some(target)) => {
                c.mounts.push(Mount {
                    harness,
                    source,
                    target,
                    read_only: ro,
                    is_dir: dir,
                });
                true
            }
            _ => false,
        }
    } else if key == b"pids_max" && tok.len() == 2 {
        once!(S_PIDS);
        match parse_number(tok[1], 1, 4_194_304) {
            Some(v) => {
                c.pids_max = v;
                true
            }
            None => false,
        }
    } else if key == b"memory_max" && tok.len() == 2 {
        once!(S_MEMORY);
        match parse_number(tok[1], 16 * 1024 * 1024, 1 << 50) {
            Some(v) => {
                c.memory_max = v;
                true
            }
            None => false,
        }
    } else if key == b"cpu_max" && tok.len() == 3 {
        once!(S_CPU);
        let quota_ok = tok[1] == b"max" || parse_number(tok[1], 1000, 1 << 40).is_some();
        let Some(period) = parse_number(tok[2], 1000, 1_000_000) else {
            return false;
        };
        if !quota_ok {
            return false;
        }
        let text = format!("{} {}", String::from_utf8_lossy(tok[1]), period);
        if text.len() >= 48 {
            return false;
        }
        c.cpu_max = text.into_bytes();
        true
    } else {
        false // unknown key or wrong arity
    }
}

fn parse_config(text: &mut [u8], c: &mut Config) -> bool {
    let mut seen = 0u32;
    let mut homes: Vec<PendingHome> = Vec::new();
    let mut pos = 0usize;
    let end = text.len();
    while pos < end {
        let line_start = pos;
        let nl = text[line_start..].iter().position(|b| *b == b'\n');
        let line_end = nl.map_or(end, |n| line_start + n);
        // Reject any control byte but tab before tokenizing.
        if text[line_start..line_end]
            .iter()
            .any(|b| (*b < 0x20 && *b != b'\t') || *b == 0x7f)
        {
            return false;
        }
        // Blank and comment lines are skipped before tokenizing, so a
        // comment may hold any number of words.
        let line = &text[line_start..line_end];
        let mut first = 0usize;
        while first < line.len() && (line[first] == b' ' || line[first] == b'\t') {
            first += 1;
        }
        if first == line.len() || line[first] == b'#' {
            pos = line_end + 1;
            continue;
        }
        // Tokenize on space/tab runs (strtok_r semantics).
        let mut toks: Vec<&[u8]> = Vec::new();
        let mut i = first;
        while i < line.len() {
            while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
                i += 1;
            }
            if i >= line.len() {
                break;
            }
            let start = i;
            while i < line.len() && line[i] != b' ' && line[i] != b'\t' {
                i += 1;
            }
            if toks.len() == 7 {
                return false;
            }
            toks.push(&line[start..i]);
        }
        if toks.is_empty() || toks.len() == 7 || !parse_line(c, &toks, &mut seen, &mut homes) {
            return false;
        }
        pos = line_end + 1;
    }
    if (seen & 7) != 7 || c.harnesses.is_empty() {
        return false;
    }
    for h in homes {
        let Some(entry) = c.harnesses.iter_mut().find(|e| e.id == h.id) else {
            return false;
        };
        entry.home_dir = h.path;
        entry.has_home_dir = true;
    }
    if c.harnesses.iter().any(|h| !h.has_home_dir) {
        return false;
    }
    if c.mounts
        .iter()
        .any(|m| find_harness(c, &m.harness).is_none())
    {
        return false;
    }
    true
}

/// `chl_load_config` — metadata checks then closed syntax.
pub fn load_config(c: &mut Config) -> Reason {
    *c = Config::default();
    c.pids_max = DEFAULT_PIDS_MAX;
    c.memory_max = DEFAULT_MEMORY_MAX;
    let path = config_path();
    let Some(cpath) = sys::bytes_cstring(&path) else {
        return Reason::ConfigInvalid;
    };
    let Ok(fd) = open(
        cpath.as_c_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) else {
        return Reason::ConfigInvalid;
    };
    let Ok(st) = fstat(&fd) else {
        return Reason::ConfigInvalid;
    };
    let mode = st.st_mode & 0o7777;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
        || st.st_uid != config_owner_uid()
        || st.st_gid != config_owner_gid()
        || st.st_nlink != 1
        || (mode != 0o600 && mode != 0o644)
        || st.st_size > CONFIG_MAX_BYTES as i64
    {
        return Reason::ConfigInvalid;
    }
    // Read the whole file, one byte past the cap.
    let mut text = vec![0u8; CONFIG_MAX_BYTES + 1];
    let mut size = 0usize;
    loop {
        match rustix::io::read(&fd, &mut text[size..]) {
            Err(Errno::INTR) => continue,
            Err(_) => {
                size = CONFIG_MAX_BYTES + 1;
                break;
            }
            Ok(0) => break,
            Ok(got) => {
                size += got;
                if size > CONFIG_MAX_BYTES {
                    break;
                }
            }
        }
    }
    text.truncate(size);
    if size > CONFIG_MAX_BYTES || text.contains(&0) || !parse_config(&mut text, c) {
        return Reason::ConfigInvalid;
    }
    Reason::Ok
}

/// `chl_find_harness`.
pub fn find_harness<'a>(c: &'a Config, id: &[u8]) -> Option<&'a HarnessEntry> {
    c.harnesses.iter().find(|h| h.id == id)
}

/* ---- identities ---- */

/// `chl_runtime_uid` — the admitted peer UID.
pub fn runtime_uid(c: &Config) -> Option<u32> {
    if let Some(uid) = knobs::peer_uid() {
        return Some(uid);
    }
    let name = sys::bytes_cstring(&c.runtime_user)?;
    sys::getpwnam(&name).map(|p| p.uid)
}

fn uid_min() -> i64 {
    let mut value: i64 = 1000;
    let path = knobs::login_defs_path().unwrap_or_else(|| LOGIN_DEFS_PATH.into());
    let Ok(text) = std::fs::read(&path) else {
        return value;
    };
    for line in text.split(|b| *b == b'\n') {
        let mut it = line
            .split(|b| *b == b' ' || *b == b'\t')
            .filter(|t| !t.is_empty());
        if let (Some(key), Some(v)) = (it.next(), it.next())
            && key == b"UID_MIN"
            && let Ok(v) = std::str::from_utf8(v).unwrap_or("").trim().parse::<i64>()
            && v > 0
        {
            value = v;
        }
    }
    value
}

fn uid_of(name: &[u8]) -> Option<u32> {
    let name = sys::bytes_cstring(name)?;
    sys::getpwnam(&name).map(|p| p.uid)
}

/// `chl_resolve_operator`.
pub fn resolve_operator(c: &Config, op: &mut Operator) -> Reason {
    let Some(name) = sys::bytes_cstring(&c.operator_user) else {
        return Reason::OperatorInvalid;
    };
    let Some(pw) = sys::getpwnam(&name) else {
        return Reason::OperatorInvalid;
    };
    if pw.uid == 0 || (pw.uid as i64) < uid_min() {
        return Reason::OperatorInvalid;
    }
    if pw.name.as_bytes() == b"central-runtime" || pw.name.as_bytes() == b"central-agent" {
        return Reason::OperatorInvalid;
    }
    op.uid = pw.uid;
    op.gid = pw.gid;
    op.name = pw.name.as_bytes().to_vec();
    op.home = pw.home.as_bytes().to_vec();
    if op.name.len() >= MAX_NAME || op.home.len() >= PATH_MAX_LEN {
        return Reason::OperatorInvalid;
    }
    if uid_of(b"central-runtime") == Some(op.uid) || uid_of(b"central-agent") == Some(op.uid) {
        return Reason::OperatorInvalid;
    }
    if let Some(h) = knobs::test_home() {
        let h = h.as_bytes();
        if h.len() >= PATH_MAX_LEN {
            return Reason::OperatorInvalid;
        }
        op.home = h.to_vec();
    }
    // The view mounts a tmpfs over HOME's parent, so HOME must have one
    // other than "/". HOME must also be canonical: with a symlink on the
    // way, the parent the view hides would not be the one that holds the
    // real home (decision 7).
    if !canonical_absolute(&op.home) || !op.home[1..].contains(&b'/') {
        return Reason::OperatorInvalid;
    }
    let Ok(real) = std::fs::canonicalize(OsStr::from_bytes(&op.home)) else {
        return Reason::OperatorInvalid;
    };
    if real.as_os_str().as_bytes() != op.home.as_slice() {
        return Reason::OperatorInvalid;
    }
    Reason::Ok
}

/* ---- worktree_root (decision 6a) ---- */

/// `test_trusted` — the trusted prefix of a test fixture (see upstream).
#[cfg(feature = "test-build")]
fn test_trusted(prefix: &[u8]) -> bool {
    let Some(trusted) = knobs::trusted_dir() else {
        return false;
    };
    let trusted = trusted.as_bytes();
    prefix.is_empty() || prefix == trusted || path_beneath(prefix, trusted)
}

/// `tree_component_ok` — a directory owned by the tree owner and writable
/// by neither group nor others. `prefix` is the absolute path of `fd`
/// ("" for "/").
fn tree_component_ok(fd: &impl AsFd, #[allow(unused_variables)] prefix: &[u8]) -> bool {
    let Ok(st) = fstat(fd) else {
        return false;
    };
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
        return false;
    }
    #[cfg(feature = "test-build")]
    {
        if test_trusted(prefix) {
            return true;
        }
    }
    st.st_uid == tree_owner_uid() && (st.st_mode & 0o022) == 0
}

fn openat2_beneath(
    dirfd: impl std::os::unix::io::AsFd,
    path: &[u8],
    flags: OFlags,
    resolve: ResolveFlags,
) -> Result<OwnedFd, Errno> {
    use std::os::unix::ffi::OsStrExt;
    // R5 task 14, D5: the `openat2` call itself lives in the shared
    // audited boundary — `resolve_with` is this shim's exact upstream
    // shape (`Mode::empty()`, `CLOEXEC` added inside). A byte path
    // with an interior NUL fails the same `INVAL` `bytes_cstring`
    // produced, one hop deeper.
    central_adapter_linux::sys::openat2::resolve_with(
        dirfd,
        std::path::Path::new(std::ffi::OsStr::from_bytes(path)),
        flags,
        resolve,
    )
}

/// `open_owned_dir` — walk the canonical absolute path from "/" with no
/// symlink, every component (and "/") passing `tree_component_ok`.
fn open_owned_dir(path: &[u8]) -> Result<OwnedFd, Errno> {
    let mut prefix: Vec<u8> = Vec::new();
    let mut cur = central_adapter_linux::sys::openat2::resolve_with(
        CWD,
        std::path::Path::new("/"),
        OFlags::PATH | OFlags::DIRECTORY,
        RESOLVE_NO_SYMLINKS,
    )?;
    if !tree_component_ok(&cur, &prefix) {
        return Err(Errno::PERM);
    }
    for part in path[1..].split(|b| *b == b'/') {
        let next = openat2_beneath(
            &cur,
            part,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            RESOLVE_STRICT,
        );
        cur = next?;
        prefix.push(b'/');
        prefix.extend_from_slice(part);
        if prefix.len() >= PATH_MAX_LEN || !tree_component_ok(&cur, &prefix) {
            return Err(Errno::PERM);
        }
    }
    Ok(cur)
}

/// `chl_open_worktree_root` — the descriptor plus its stat.
pub fn open_worktree_root(c: &Config) -> Result<(OwnedFd, Stat), Errno> {
    let fd = open_owned_dir(&c.worktree_root)?;
    let st = fstat(&fd)?;
    Ok((fd, st))
}

/// `open_owned_program` — a program outside HOME: reached like
/// worktree_root, itself a file of the tree owner.
fn open_owned_program(program: &[u8]) -> Result<OwnedFd, Errno> {
    let Some(slash) = program.iter().rposition(|b| *b == b'/') else {
        return Err(Errno::INVAL);
    };
    let parent = open_owned_dir(if slash == 0 { b"/" } else { &program[..slash] })?;
    let fd = openat2_beneath(
        &parent,
        &program[slash + 1..],
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        RESOLVE_STRICT,
    )?;
    let st = fstat(&fd)?;
    if st.st_uid != tree_owner_uid() || (st.st_mode & 0o022) != 0 {
        return Err(Errno::PERM);
    }
    Ok(fd)
}

/* ---- HOME-dependent configuration ---- */

/// `hidden_by_view` — the mount view replaces these trees with tmpfs.
fn hidden_by_view(c: &Config, op: &Operator, path: &[u8]) -> bool {
    let mut parent = op.home.clone();
    if let Some(s) = parent.iter().rposition(|b| *b == b'/') {
        parent.truncate(s);
    }
    let hidden: [&[u8]; 7] = [
        b"/tmp",
        b"/var/tmp",
        b"/root",
        b"/run/user",
        b"/dev/shm",
        &parent,
        &c.worktree_root,
    ];
    hidden.iter().any(|h| same_or_beneath(h, path))
}

/// `chl_check_home_config` — returns the worktree_root identity.
pub fn check_home_config(c: &Config, op: &Operator) -> Result<Stat, Reason> {
    if same_or_beneath(&op.home, &c.worktree_root) || same_or_beneath(&c.worktree_root, &op.home) {
        return Err(Reason::ConfigInvalid);
    }
    let (root_fd, st) = open_worktree_root(c).map_err(|_| Reason::ConfigInvalid)?;
    drop(root_fd);
    for h in &c.harnesses {
        if same_or_beneath(&op.home, &h.program) {
            // The view shows the program at its own path, read-only, only
            // through an ro dir entry mapped onto the same HOME-relative
            // path. No other entry of the harness may overlap that target,
            // and no rw entry (incl. any home_dir) may overlap its source.
            let mut under_ro = false;
            for (j, m) in c.mounts.iter().enumerate() {
                if m.harness != h.id || !m.read_only || !m.is_dir || m.source != m.target {
                    continue;
                }
                let mut source = op.home.clone();
                source.push(b'/');
                source.extend_from_slice(&m.source);
                if !path_beneath(&source, &h.program) {
                    continue;
                }
                under_ro = true;
                for (k, o) in c.mounts.iter().enumerate() {
                    if k == j {
                        continue;
                    }
                    if o.harness == h.id
                        && (same_or_beneath(&m.target, &o.target)
                            || same_or_beneath(&o.target, &m.target))
                    {
                        return Err(Reason::ConfigInvalid);
                    }
                    if !o.read_only
                        && (same_or_beneath(&m.source, &o.source)
                            || same_or_beneath(&o.source, &m.source))
                    {
                        return Err(Reason::ConfigInvalid);
                    }
                }
                // Every harness's home_dir is bound read-write as HOME in
                // its own view (decision 9), so it is an implicit rw
                // source too.
                for ge in &c.harnesses {
                    if same_or_beneath(&ge.home_dir, &m.source)
                        || same_or_beneath(&m.source, &ge.home_dir)
                    {
                        return Err(Reason::ConfigInvalid);
                    }
                }
            }
            if !under_ro {
                return Err(Reason::ConfigInvalid);
            }
        } else if !knobs::no_isolation() && hidden_by_view(c, op, &h.program) {
            return Err(Reason::ConfigInvalid);
        }
    }
    Ok(st)
}

fn open_type_ok(fd: Result<OwnedFd, Errno>, want_dir: bool) -> bool {
    let Ok(fd) = fd else { return false };
    let Ok(st) = fstat(&fd) else { return false };
    let want = if want_dir {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    FileType::from_raw_mode(st.st_mode) == want
}

/// `chl_check_harness_home` — the harness home, its mount points and the
/// mount sources; the program as an executable regular file.
pub fn check_harness_home(c: &Config, op: &Operator, h: &HarnessEntry) -> Reason {
    let Some(home_c) = sys::bytes_cstring(&op.home) else {
        return Reason::ConfigInvalid;
    };
    let Ok(home) = open(
        home_c.as_c_str(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return Reason::ConfigInvalid;
    };
    let Ok(harness_home) = openat2_beneath(
        &home,
        &h.home_dir,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        RESOLVE_STRICT,
    ) else {
        return Reason::ConfigInvalid;
    };
    for m in &c.mounts {
        if m.harness != h.id {
            continue;
        }
        let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if !open_type_ok(
            openat2_beneath(&home, &m.source, flags, RESOLVE_STRICT),
            m.is_dir,
        ) {
            return Reason::ConfigInvalid;
        }
        if !open_type_ok(
            openat2_beneath(&harness_home, &m.target, flags, RESOLVE_STRICT),
            m.is_dir,
        ) {
            return Reason::ConfigInvalid;
        }
    }
    let program = if path_beneath(&op.home, &h.program) {
        openat2_beneath(
            &home,
            &h.program[op.home.len() + 1..],
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            RESOLVE_STRICT,
        )
    } else {
        open_owned_program(&h.program)
    };
    let Ok(program) = program else {
        return Reason::ConfigInvalid;
    };
    let Ok(st) = fstat(&program) else {
        return Reason::ConfigInvalid;
    };
    if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile && (st.st_mode & 0o111) != 0 {
        Reason::Ok
    } else {
        Reason::ConfigInvalid
    }
}

/* ---- argv grammar (decision 10) ---- */

/// `chl_harness_has_grammar`.
pub fn harness_has_grammar(harness: &[u8]) -> bool {
    harness == b"claude"
        || harness == b"opencode"
        || harness == b"codex"
        || harness == b"antigravity"
}

fn canonical_uuid(s: &[u8]) -> bool {
    if s.len() != 36 {
        return false;
    }
    for (i, &c) in s.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if c != b'-' {
                return false;
            }
        } else if !(c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return false;
        }
    }
    true
}

/// `valid_model` — mirrors the claudecode adapter's safeModel.
fn valid_model(m: &[u8]) -> bool {
    if m.is_empty() || m.len() > 128 || m[0] == b'-' {
        return false;
    }
    m.iter().all(|c| {
        c.is_ascii_alphanumeric()
            || *c == b'-'
            || *c == b'.'
            || *c == b'_'
            || *c == b':'
            || *c == b'/'
            || *c == b'['
            || *c == b']'
            || *c == b'@'
    })
}

/// `valid_budget_usd` — mirrors formatCostUSD: "<dollars>.<cents>", 1-4
/// integer digits, no leading zero unless the dollar part is "0",
/// exactly two decimals, 0.01..=1000.00.
fn valid_budget_usd(a: &[u8]) -> bool {
    let n = a.len();
    if !(4..=7).contains(&n) {
        return false;
    }
    let dot = n - 3;
    if a[dot] != b'.' {
        return false;
    }
    if a[0] == b'0' && dot > 1 {
        return false;
    }
    let mut cents: i64 = 0;
    for (i, &c) in a.iter().enumerate() {
        if i == dot {
            continue;
        }
        if !c.is_ascii_digit() {
            return false;
        }
        cents = cents * 10 + i64::from(c - b'0');
    }
    (1..=100000).contains(&cents)
}

/// `match_seq` — argv[at..] starts with seq; advances `at`.
fn match_seq<'a>(argv: &[&'a [u8]], at: &mut usize, seq: &[&'a [u8]]) -> bool {
    if *at + seq.len() > argv.len() {
        return false;
    }
    for (i, s) in seq.iter().enumerate() {
        if argv[*at + i] != *s {
            return false;
        }
    }
    *at += seq.len();
    true
}

fn claude_argv_kind(argv: &[&[u8]]) -> ArgvKind {
    if argv.len() == 1 && argv[0] == b"--version" {
        return ArgvKind::Probe;
    }
    if argv.len() == 2 && argv[0] == b"auth" && argv[1] == b"status" {
        return ArgvKind::Probe;
    }
    const PREFIX: &[&[u8]] = &[
        b"-p",
        b"--verbose",
        b"--output-format",
        b"stream-json",
        b"--input-format",
        b"stream-json",
        b"--setting-sources",
        b"user",
    ];
    const DENY: &[&[u8]] = &[
        b"--permission-mode",
        b"dontAsk",
        b"--permission-prompts",
        b"none",
    ];
    const BRIDGE: &[&[u8]] = &[
        b"--permission-mode",
        b"manual",
        b"--permission-prompts",
        b"host",
        b"--permission-prompt-tool",
        b"stdio",
    ];
    const BYPASS: &[&[u8]] = &[b"--permission-mode", b"bypassPermissions"];
    let mut at = 0;
    if !match_seq(argv, &mut at, PREFIX) {
        return ArgvKind::Refused;
    }
    if at + 2 > argv.len()
        || (argv[at] != b"--session-id" && argv[at] != b"--resume")
        || !canonical_uuid(argv[at + 1])
    {
        return ArgvKind::Refused;
    }
    at += 2;
    if !match_seq(argv, &mut at, DENY)
        && !match_seq(argv, &mut at, BRIDGE)
        && !match_seq(argv, &mut at, BYPASS)
    {
        return ArgvKind::Refused;
    }
    if at + 2 <= argv.len() && argv[at] == b"--model" && valid_model(argv[at + 1]) {
        at += 2;
    }
    if at + 2 <= argv.len() && argv[at] == b"--max-budget-usd" && valid_budget_usd(argv[at + 1]) {
        at += 2;
    }
    if at == argv.len() {
        ArgvKind::Session
    } else {
        ArgvKind::Refused
    }
}

/// `valid_ses_id` — opencode's `ses_` plus 1-64 ASCII alnum.
fn valid_ses_id(s: &[u8]) -> bool {
    if s.len() < 5 || s.len() > 68 || &s[..4] != b"ses_" {
        return false;
    }
    s[4..].iter().all(|c| c.is_ascii_alphanumeric())
}

fn opencode_argv_kind(argv: &[&[u8]]) -> ArgvKind {
    if argv.len() == 1 && argv[0] == b"--version" {
        return ArgvKind::Probe;
    }
    const PREFIX: &[&[u8]] = &[b"run", b"--format", b"json"];
    let mut at = 0;
    if !match_seq(argv, &mut at, PREFIX) {
        return ArgvKind::Refused;
    }
    if at + 2 <= argv.len() && argv[at] == b"--model" && valid_model(argv[at + 1]) {
        at += 2;
    }
    if at + 2 <= argv.len() && argv[at] == b"--session" && valid_ses_id(argv[at + 1]) {
        at += 2;
    }
    if at == argv.len() {
        ArgvKind::Session
    } else {
        ArgvKind::Refused
    }
}

fn codex_argv_kind(argv: &[&[u8]]) -> ArgvKind {
    if argv.len() == 1 && argv[0] == b"--version" {
        return ArgvKind::Probe;
    }
    if argv.len() == 2 && argv[0] == b"login" && argv[1] == b"status" {
        return ArgvKind::Probe;
    }
    const FRESH: &[&[u8]] = &[b"exec", b"--json", b"-s", b"workspace-write"];
    const RESUME: &[&[u8]] = &[
        b"exec",
        b"resume",
        b"--json",
        b"-c",
        b"sandbox_mode=\"workspace-write\"",
    ];
    let mut at = 0;
    let is_resume = if match_seq(argv, &mut at, RESUME) {
        true
    } else if match_seq(argv, &mut at, FRESH) {
        false
    } else {
        return ArgvKind::Refused;
    };
    if at + 2 <= argv.len() && argv[at] == b"--model" && valid_model(argv[at + 1]) {
        at += 2;
    }
    if is_resume {
        if at + 1 > argv.len() || !canonical_uuid(argv[at]) {
            return ArgvKind::Refused;
        }
        at += 1;
    }
    if at + 1 != argv.len() || argv[at] != b"-" {
        return ArgvKind::Refused;
    }
    ArgvKind::Session
}

fn antigravity_argv_kind(argv: &[&[u8]]) -> ArgvKind {
    if argv.len() == 1 && argv[0] == b"--version" {
        return ArgvKind::Probe;
    }
    const PREFIX: &[&[u8]] = &[
        b"--input-format",
        b"stream-json",
        b"--output-format",
        b"stream-json",
        b"--disable-slash-commands",
    ];
    let mut at = 0;
    if !match_seq(argv, &mut at, PREFIX) {
        return ArgvKind::Refused;
    }
    if at + 2 <= argv.len() && argv[at] == b"--model" && valid_model(argv[at + 1]) {
        at += 2;
    }
    if at + 2 <= argv.len() && argv[at] == b"--conversation" && canonical_uuid(argv[at + 1]) {
        at += 2;
    }
    if at == argv.len() {
        ArgvKind::Session
    } else {
        ArgvKind::Refused
    }
}

/// `chl_argv_kind` — the harness's compiled grammar.
pub fn argv_kind(harness: &[u8], argv: &[&[u8]]) -> ArgvKind {
    if harness == b"claude" {
        return claude_argv_kind(argv);
    }
    if harness == b"opencode" {
        return opencode_argv_kind(argv);
    }
    if harness == b"codex" {
        return codex_argv_kind(argv);
    }
    if harness == b"antigravity" {
        return antigravity_argv_kind(argv);
    }
    ArgvKind::Refused
}

/* ---- env (decision 11): mirrors internal/harness/env.go ---- */

const BASE_ALLOWED: &[&[u8]] = &[
    b"PATH",
    b"LANG",
    b"LANGUAGE",
    b"TERM",
    b"COLORTERM",
    b"NO_COLOR",
    b"TZ",
    b"TMPDIR",
    b"USER",
    b"LOGNAME",
    b"SHELL",
    b"CENTRAL_ATTEMPT_SCOPE",
    b"AGY_CLI_DISABLE_AUTO_UPDATE",
];
const DENIED_EXACT: &[&[u8]] = &[
    b"HOME",
    b"CLAUDE_CONFIG_DIR",
    b"OPENCODE_CONFIG_DIR",
    b"OPENCODE_CONFIG",
    b"OPENCODE_CONFIG_CONTENT",
    b"OPENCODE_DB",
    b"CODEX_HOME",
    b"HTTP_PROXY",
    b"HTTPS_PROXY",
    b"ALL_PROXY",
    b"NO_PROXY",
    b"SSL_CERT_FILE",
    b"SSL_CERT_DIR",
    b"REQUESTS_CA_BUNDLE",
    b"CURL_CA_BUNDLE",
    b"GOOGLE_APPLICATION_CREDENTIALS",
];
const DENIED_PREFIXES: &[&[u8]] = &[
    b"XDG_",
    b"NODE_",
    b"ANTHROPIC_",
    b"CLAUDE_CODE_",
    b"OPENAI_",
    b"OPENCODE_",
    b"AWS_",
    b"GOOGLE_",
    b"GEMINI_",
    b"META_",
    b"AZURE_",
    b"LD_",
    b"DYLD_",
];
const DENIED_SUFFIXES: &[&[u8]] = &[
    b"_TOKEN",
    b"_API_KEY",
    b"_KEY",
    b"_SECRET",
    b"_SECRET_ACCESS_KEY",
    b"_ACCESS_KEY_ID",
    b"_PASSWORD",
    b"_CREDENTIALS",
    b"_BASE_URL",
    b"_CUSTOM_HEADERS",
    b"_PROXY",
];

fn env_name_valid(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    for (i, &ch) in name.iter().enumerate() {
        let letter = ch == b'_' || ch.is_ascii_uppercase() || ch.is_ascii_lowercase();
        if !letter && (i == 0 || !ch.is_ascii_digit()) {
            return false;
        }
    }
    true
}

fn env_name_denied(name: &[u8]) -> bool {
    let upper: Vec<u8> = name.iter().map(|c| c.to_ascii_uppercase()).collect();
    if DENIED_EXACT.iter().any(|d| upper == *d) {
        return true;
    }
    if DENIED_PREFIXES.iter().any(|d| upper.starts_with(d)) {
        return true;
    }
    DENIED_SUFFIXES
        .iter()
        .any(|d| upper.len() >= d.len() && upper[upper.len() - d.len()..] == **d)
}

fn env_name_allowed(name: &[u8]) -> bool {
    if name.len() >= 3 && &name[..3] == b"LC_" {
        return true;
    }
    BASE_ALLOWED.contains(&name)
}

/// `chl_env_allowed` — every entry's name must be valid, allowed and not
/// denied.
pub fn env_allowed(env: &[Vec<u8>]) -> bool {
    for e in env {
        let Some(eq) = e.iter().position(|b| *b == b'=') else {
            return false;
        };
        let name = &e[..eq];
        if !env_name_valid(name) || !env_name_allowed(name) || env_name_denied(name) {
            return false;
        }
    }
    true
}

/// `chl_build_env` — the request env minus USER/LOGNAME/HOME, then HOME,
/// USER and LOGNAME from passwd.
pub fn build_env(env: &[Vec<u8>], op: &Operator) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(env.len() + 3);
    for e in env {
        if e.starts_with(b"USER=") || e.starts_with(b"LOGNAME=") || e.starts_with(b"HOME=") {
            continue;
        }
        out.push(e.clone());
    }
    let mut home = b"HOME=".to_vec();
    home.extend_from_slice(&op.home);
    out.push(home);
    let mut user = b"USER=".to_vec();
    user.extend_from_slice(&op.name);
    out.push(user);
    let mut logname = b"LOGNAME=".to_vec();
    logname.extend_from_slice(&op.name);
    out.push(logname);
    out
}

/* ---- workdir ---- */

/// `chl_check_workdir`.
pub fn check_workdir(c: &Config, workdir: &[u8], kind: ArgvKind, root_id: &Stat) -> Reason {
    if workdir.is_empty() {
        return if kind == ArgvKind::Probe {
            Reason::Ok
        } else {
            Reason::WorkdirInvalid
        };
    }
    if !canonical_relative(workdir) {
        return Reason::WorkdirInvalid;
    }
    let Ok((root, st)) = open_worktree_root(c) else {
        return Reason::ConfigInvalid;
    };
    if st.st_dev != root_id.st_dev || st.st_ino != root_id.st_ino {
        return Reason::ConfigInvalid;
    }
    match openat2_beneath(
        &root,
        workdir,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        RESOLVE_STRICT,
    ) {
        Ok(_) => Reason::Ok,
        Err(_) => Reason::WorkdirInvalid,
    }
}
