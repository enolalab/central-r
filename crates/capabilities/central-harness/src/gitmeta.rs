//! `gitmeta` — the bounded grammar of the untrusted clone: the
//! name allowlists, ref grammar and loose-object header check that
//! upstream `internal/adapter/workspace/gitclone` ports evaluate while
//! reading a Run's sealed work tree (harness phase 3b decisions 4–6).
//!
//! Everything here is pure: no I/O, no syscalls. The two sealer
//! implementations share it — `central-adapter-linux::workspace_seal`
//! drives it over `openat2` descriptors and the `gitclone` test sealer
//! over plain paths — so the accept/reject decision is identical on
//! both sides of the D2 seam.
//!
//! All functions take byte slices: path components and ref names are
//! untrusted and may be non-UTF-8.

/// Upstream `objectIDPattern`/`shaPattern` — a 40- or 64-hex object id.
#[must_use]
pub fn is_object_id(s: &[u8]) -> bool {
    (s.len() == 40 || s.len() == 64) && is_lower_hex(s)
}

fn is_lower_hex(s: &[u8]) -> bool {
    s.iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// Upstream `looseDirPattern` — `^[0-9a-f]{2}$`.
#[must_use]
pub fn is_loose_dir_name(name: &[u8]) -> bool {
    name.len() == 2 && is_lower_hex(name)
}

/// Upstream `looseObjectPattern` — `^[0-9a-f]{38}|[0-9a-f]{62}$`.
#[must_use]
pub fn is_loose_object_name(name: &[u8]) -> bool {
    (name.len() == 38 || name.len() == 62) && is_lower_hex(name)
}

/// Upstream `packFilePattern` —
/// `^pack-(?:[0-9a-f]{40}|[0-9a-f]{64})\.(?:pack|idx|rev)$`.
#[must_use]
pub fn is_pack_file_name(name: &[u8]) -> bool {
    let Some(stem) = name.strip_prefix(b"pack-") else {
        return false;
    };
    for ext in [b".pack".as_slice(), b".idx", b".rev"] {
        if let Some(hex) = stem.strip_suffix(ext) {
            return (hex.len() == 40 || hex.len() == 64) && is_lower_hex(hex);
        }
    }
    false
}

/// `refComponentPattern` — one ref component: `[A-Za-z0-9_+-]` then
/// `[A-Za-z0-9._+-]*` (a strict subset of `git check-ref-format`).
fn is_ref_component(part: &[u8]) -> bool {
    if part.is_empty() {
        return false;
    }
    let ok_first = matches!(part[0], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'+' | b'-');
    if !ok_first {
        return false;
    }
    part[1..]
        .iter()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'-'))
}

/// Upstream `validRefName` — `refs/<component>/...` with strict
/// components: no `..`, no trailing dot, no `.lock` suffix, at most 255
/// bytes.
#[must_use]
pub fn valid_ref_name(name: &[u8]) -> bool {
    if name.len() > 255 || !name.starts_with(b"refs/") || contains_bytes(name, b"..") {
        return false;
    }
    let parts: Vec<&[u8]> = name.split(|b| *b == b'/').collect();
    if parts.len() < 3 {
        return false;
    }
    parts
        .iter()
        .all(|part| is_ref_component(part) && !part.ends_with(b".") && !part.ends_with(b".lock"))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Upstream `oneLine` — `data` without one trailing `\n`, or `None`
/// when anything else follows its first line.
#[must_use]
pub fn one_line(data: &[u8]) -> Option<&[u8]> {
    let s = data.strip_suffix(b"\n").unwrap_or(data);
    if s.iter().any(|b| *b == b'\n' || *b == b'\r') {
        return None;
    }
    Some(s)
}

/// The sealed clone's HEAD — upstream's two accepted shapes: a raw
/// object id or `ref: <name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadRef {
    /// A detached HEAD — the object id it names.
    Detached(Vec<u8>),
    /// `ref: <name>` — the ref to resolve (loose first, then packed).
    Symbolic(Vec<u8>),
}

/// Upstream's HEAD parse in `readAfterHEAD`: one line that is an object
/// id or `ref: <valid ref>`; anything else is unavailable.
#[must_use]
pub fn parse_head(data: &[u8]) -> Option<HeadRef> {
    let head = one_line(data)?;
    if is_object_id(head) {
        return Some(HeadRef::Detached(head.to_vec()));
    }
    let r = head.strip_prefix(b"ref: ")?;
    if !valid_ref_name(r) {
        return None;
    }
    Some(HeadRef::Symbolic(r.to_vec()))
}

/// Upstream `packedRef` — finds `want` in `packed-refs` data. Every
/// line must be the header, a peeled `^<id>` line or `<id> <refname>`;
/// anything else makes the file unusable. The last match wins.
#[must_use]
pub fn packed_ref_lookup(data: &[u8], want: &[u8]) -> Option<Vec<u8>> {
    let body = data.strip_suffix(b"\n").unwrap_or(data);
    let mut found: Option<Vec<u8>> = None;
    for (i, line) in body.split(|b| *b == b'\n').enumerate() {
        if i == 0 && line.starts_with(b"# pack-refs with:") {
            continue;
        }
        if let Some(id) = line.strip_prefix(b"^") {
            if !is_object_id(id) {
                return None;
            }
            continue;
        }
        let (id, name) = split_once(line, b' ')?;
        if !is_object_id(id) || !valid_ref_name(name) {
            return None;
        }
        if name == want {
            found = Some(id.to_vec());
        }
    }
    found
}

fn split_once(s: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let pos = s.iter().position(|b| *b == sep)?;
    Some((&s[..pos], &s[pos + 1..]))
}

/// `maxLooseHeaderObjectBytes` — the largest size a loose commit, tree
/// or tag may declare (16 MiB). Git inflates such an object whole when
/// it reads it, so a small zlib bomb declaring gigabytes would exhaust
/// the capture's memory.
pub const MAX_LOOSE_HEADER_OBJECT_BYTES: i64 = 16 << 20;

/// Upstream `looseHeaderAcceptable` — inflates only the loose object's
/// header, `<type> <size>\0`, and accepts a well-formed header whose
/// commit, tree or tag does not declare more than
/// [`MAX_LOOSE_HEADER_OBJECT_BYTES`]. Blob headers are not
/// size-checked. A malformed stream or header is not acceptable.
#[must_use]
pub fn loose_header_acceptable(data: &[u8]) -> bool {
    let Some(header) = inflate_prefix(data, 32) else {
        return false;
    };
    let Some(end) = header.iter().position(|b| *b == 0) else {
        return false;
    };
    let Ok(head) = core::str::from_utf8(&header[..end]) else {
        return false;
    };
    let Some((kind, size)) = head.split_once(' ') else {
        return false;
    };
    if size.is_empty() || size.len() > 19 || !size.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // i64 parse, matching upstream's strconv.ParseInt(10, 64): an
    // all-digit 19-digit size can still overflow it.
    let Ok(declared) = size.parse::<i64>() else {
        return false;
    };
    match kind {
        "blob" => true,
        "commit" | "tree" | "tag" => declared <= MAX_LOOSE_HEADER_OBJECT_BYTES,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Bounded zlib/DEFLATE decode — the `compress/zlib` reader of
// `looseHeaderAcceptable`, implemented in-tree because the workspace
// pins no compression crate. It decodes RFC 1950/1951 streams (stored,
// fixed and dynamic Huffman blocks, LZ77 copies within the produced
// output) and stops once `cap` output bytes are produced: for the
// header check only the first 32 output bytes matter.
// ---------------------------------------------------------------------------

/// Inflates `data` (a zlib stream) producing at most `cap` output
/// bytes. `None` on a malformed stream — the same refusal upstream's
/// `zlib.NewReader`/`io.ReadFull` error path makes. Stopping at `cap`
/// is success, not an error.
#[must_use]
pub fn inflate_prefix(data: &[u8], cap: usize) -> Option<Vec<u8>> {
    Inflater::new(data, cap).run()
}

struct Inflater<'a> {
    data: &'a [u8],
    bit: usize, // absolute bit position
    out: Vec<u8>,
    cap: usize,
}

/// One canonical Huffman decoder — puff's `struct huffman`: decode-time
/// `counts`/`symbols` with no materialized table.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

/// `puff`'s fixed literal/length code lengths (288) and distance code
/// lengths (30), and the dynamic block's code-length order.
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
/// Base lengths and extra bits for length symbols 257..=285.
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// Base distances and extra bits for distance symbols 0..=29.
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

impl<'a> Inflater<'a> {
    fn new(data: &'a [u8], cap: usize) -> Self {
        Self {
            data,
            bit: 0,
            out: Vec::new(),
            cap,
        }
    }

    fn run(mut self) -> Option<Vec<u8>> {
        // zlib header: CMF (CM 8, CINFO ≤ 7) and FLG with FCHECK; FDICT
        // (0x20) is refused — git never sets it.
        if self.data.len() < 2 {
            return None;
        }
        let cmf = u32::from(self.data[0]);
        let flg = u32::from(self.data[1]);
        if cmf & 0x0f != 8 || cmf >> 4 > 7 || (cmf * 256 + flg) % 31 != 0 || flg & 0x20 != 0 {
            return None;
        }
        self.bit = 16;
        loop {
            let last = self.bits(1)? == 1;
            match self.bits(2)? {
                0 => self.stored()?,
                1 => {
                    // Fixed Huffman block — RFC 1951 §3.2.6 lengths.
                    let mut lit_len = [0u8; 288];
                    lit_len[..144].fill(8);
                    lit_len[144..256].fill(9);
                    lit_len[256..280].fill(7);
                    lit_len[280..].fill(8);
                    let mut dist_len = [0u8; 30];
                    dist_len.fill(5);
                    let (lit, dist) = (build(&lit_len), build(&dist_len));
                    self.huffman_block(&lit, &dist)?;
                }
                2 => {
                    let (lit, dist) = self.dynamic()?;
                    self.huffman_block(&lit, &dist)?;
                }
                _ => return None,
            }
            if self.out.len() >= self.cap || last {
                return Some(self.out);
            }
        }
    }

    /// One input bit, LSB-first in each byte (RFC 1951 §3.1.1).
    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for i in 0..n {
            let byte = self.data.get(self.bit / 8)?;
            v |= u32::from(byte >> (self.bit % 8) & 1) << i;
            self.bit += 1;
        }
        Some(v)
    }

    /// A stored block — drop partial bits to the byte boundary, then
    /// LEN/NLEN and LEN raw bytes, bounded by the output cap.
    fn stored(&mut self) -> Option<()> {
        self.bit = self.bit.div_ceil(8) * 8;
        let p = self.bit / 8;
        let hdr = self.data.get(p..p + 4)?;
        let len = usize::from(u16::from_le_bytes([hdr[0], hdr[1]]));
        let nlen = usize::from(u16::from_le_bytes([hdr[2], hdr[3]]));
        if len != !nlen & 0xffff {
            return None;
        }
        self.bit = (p + 4) * 8;
        let room = self.cap - self.out.len();
        let take = len.min(room);
        self.out
            .extend_from_slice(self.data.get(p + 4..p + 4 + take)?);
        // Consume the whole block's input position even though only
        // `take` bytes were emitted — the stream continues past it.
        self.bit = (p + 4 + len) * 8;
        Some(())
    }

    /// Reads the dynamic block's two code-length tables.
    fn dynamic(&mut self) -> Option<(Huffman, Huffman)> {
        let n_lit = self.bits(5)? as usize + 257;
        let n_dist = self.bits(5)? as usize + 1;
        let n_len = self.bits(4)? as usize + 4;
        if n_lit > 286 || n_dist > 30 {
            return None;
        }
        let mut clen = [0u8; 19];
        for i in 0..n_len {
            let slot = CODE_LENGTH_ORDER.get(i)?;
            clen[*slot] = self.bits(3)? as u8;
        }
        let clen_huff = build(&clen);
        let mut lengths = vec![0u8; n_lit + n_dist];
        let mut i = 0;
        while i < n_lit + n_dist {
            let sym = self.decode(&clen_huff)?;
            match sym {
                0..=15 => {
                    lengths[i] = sym as u8;
                    i += 1;
                }
                16 => {
                    if i == 0 {
                        return None;
                    }
                    let prev = lengths[i - 1];
                    let rep = 3 + self.bits(2)? as usize;
                    for _ in 0..rep {
                        *lengths.get_mut(i)? = prev;
                        i += 1;
                    }
                }
                17 => {
                    let rep = 3 + self.bits(3)? as usize;
                    i += rep;
                    if i > n_lit + n_dist {
                        return None;
                    }
                }
                18 => {
                    let rep = 11 + self.bits(7)? as usize;
                    i += rep;
                    if i > n_lit + n_dist {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        let lit = build(&lengths[..n_lit]);
        let dist = build(&lengths[n_lit..]);
        Some((lit, dist))
    }

    /// Decodes one compressed block until the end-of-block symbol, the
    /// output cap, or the stored-block fallthrough.
    fn huffman_block(&mut self, lit: &Huffman, dist: &Huffman) -> Option<()> {
        loop {
            if self.out.len() >= self.cap {
                return Some(());
            }
            let sym = self.decode(lit)?;
            match sym {
                0..=255 => {
                    if self.out.len() >= self.cap {
                        return Some(());
                    }
                    self.out.push(sym as u8);
                }
                256 => return Some(()),
                257..=285 => {
                    let idx = usize::from(sym - 257);
                    let len =
                        usize::from(LENGTH_BASE[idx]) + self.bits(LENGTH_EXTRA[idx])? as usize;
                    let dsym = self.decode(dist)?;
                    if dsym > 29 {
                        return None;
                    }
                    let didx = usize::from(dsym);
                    let distance =
                        usize::from(DIST_BASE[didx]) + self.bits(DIST_EXTRA[didx])? as usize;
                    if distance > self.out.len() {
                        return None; // a copy may only reach into output produced so far
                    }
                    for _ in 0..len {
                        if self.out.len() >= self.cap {
                            return Some(());
                        }
                        let b = self.out[self.out.len() - distance];
                        self.out.push(b);
                    }
                }
                _ => return None, // 286/287 never appear
            }
        }
    }

    /// puff's `decode`: walk the canonical code bit by bit.
    fn decode(&mut self, h: &Huffman) -> Option<u16> {
        let mut code = 0u32;
        let mut first = 0u32;
        let mut index = 0usize;
        for len in 1..16 {
            code |= self.bits(1)?;
            let count = u32::from(h.counts[len]);
            if code < first + count {
                return h.symbols.get(index + (code - first) as usize).copied();
            }
            index += count as usize;
            first = (first + count) << 1;
            code <<= 1;
        }
        None
    }
}

/// Builds a canonical decoder from code lengths (`puff`'s `construct`):
/// `counts[len]` symbols sorted by (length, symbol order).
fn build(lengths: &[u8]) -> Huffman {
    let mut counts = [0u16; 16];
    for &l in lengths {
        counts[usize::from(l)] += 1;
    }
    counts[0] = 0;
    let mut offs = [0usize; 16];
    for len in 1..16 {
        offs[len] = offs[len - 1] + usize::from(counts[len - 1]);
    }
    let symbols: Vec<u16> = {
        let mut v = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                v[offs[usize::from(l)]] = sym as u16;
                offs[usize::from(l)] += 1;
            }
        }
        v
    };
    Huffman { counts, symbols }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored-block zlib stream — the smallest valid compressor, used
    /// to fixture loose objects without a compression dependency.
    fn zstore(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x78, 0x01];
        let mut rest = data;
        loop {
            let n = rest.len().min(0xffff);
            let last = n == rest.len();
            out.push(u8::from(last));
            let len = n as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
            if last {
                break;
            }
        }
        // Adler-32, big-endian.
        let (mut a, mut b) = (1u32, 0u32);
        for &byte in data {
            a = (a + u32::from(byte)) % 65521;
            b = (b + a) % 65521;
        }
        out.extend_from_slice(&(b << 16 | a).to_be_bytes());
        out
    }

    #[test]
    fn object_id_grammar() {
        assert!(is_object_id(b"0123456789abcdef0123456789abcdef01234567"));
        assert!(is_object_id(
            b"0123456789abcdef0123456789abcdef012345670123456789abcdef01234567"
        ));
        assert!(!is_object_id(b"0123456789abcdef0123456789abcdef0123456")); // 39
        assert!(!is_object_id(b"0123456789ABCDEF0123456789abcdef01234567"));
        assert!(!is_object_id(b""));
    }

    #[test]
    fn object_name_grammar() {
        assert!(is_loose_dir_name(b"ab"));
        assert!(!is_loose_dir_name(b"abc") && !is_loose_dir_name(b"AB"));
        assert!(is_loose_object_name(
            b"0123456789abcdef0123456789abcdef012345"
        ));
        assert!(is_loose_object_name(
            b"0123456789abcdef0123456789abcdef012345670123456789abcdef012345"
        ));
        assert!(!is_loose_object_name(
            b"not-hex-not-hex-not-hex-not-hex-not-he"
        ));
        assert!(is_pack_file_name(
            b"pack-0123456789abcdef0123456789abcdef01234567.pack"
        ));
        assert!(is_pack_file_name(
            b"pack-0123456789abcdef0123456789abcdef01234567.idx"
        ));
        assert!(is_pack_file_name(
            b"pack-0123456789abcdef0123456789abcdef012345670123456789abcdef01234567.rev"
        ));
        assert!(!is_pack_file_name(
            b"pack-0123456789abcdef0123456789abcdef01234567.bitmap"
        ));
        assert!(!is_pack_file_name(b"multi-pack-index"));
        assert!(!is_pack_file_name(b"pack-zz.idx"));
    }

    #[test]
    fn ref_name_grammar() {
        assert!(valid_ref_name(b"refs/heads/main"));
        assert!(valid_ref_name(b"refs/heads/feature/x.y-z+1"));
        let bads: Vec<Vec<u8>> = vec![
            b"refs/heads/../etc".to_vec(),
            b"refs/heads/main.lock".to_vec(),
            b"refs/heads/main.".to_vec(),
            b"refs/heads//double".to_vec(),
            b"refs/only".to_vec(),
            b"config".to_vec(),
            b"refs/.heads/x".to_vec(),
            vec![b'a'; 260],
        ];
        for bad in &bads {
            assert!(!valid_ref_name(bad), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn head_and_packed_refs() {
        let sha = b"0123456789abcdef0123456789abcdef01234567";
        let other = b"89abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(parse_head(sha), Some(HeadRef::Detached(sha.to_vec())));
        let mut head = sha.to_vec();
        head.push(b'\n');
        assert_eq!(parse_head(&head), Some(HeadRef::Detached(sha.to_vec())));
        assert_eq!(
            parse_head(b"ref: refs/heads/feature/x\n"),
            Some(HeadRef::Symbolic(b"refs/heads/feature/x".to_vec()))
        );
        assert_eq!(parse_head(b"hello\n"), None);
        assert_eq!(parse_head(b"ref: config\n"), None);
        let mut packed = b"# pack-refs with: peeled fully-peeled sorted \n".to_vec();
        packed.extend_from_slice(other);
        packed.extend_from_slice(b" refs/heads/aaa\n");
        packed.extend_from_slice(sha);
        packed.extend_from_slice(b" refs/heads/main\n^");
        packed.extend_from_slice(other);
        packed.push(b'\n');
        packed.extend_from_slice(other);
        packed.extend_from_slice(b" refs/tags/v1\n");
        assert_eq!(
            packed_ref_lookup(&packed, b"refs/heads/main"),
            Some(sha.to_vec())
        );
        assert_eq!(packed_ref_lookup(&packed, b"refs/heads/zzz"), None);
        // A malformed line makes the file unusable.
        let bad = [&sha[..], b" refs/heads/main\nnot a line\n"].concat();
        assert_eq!(packed_ref_lookup(&bad, b"refs/heads/main"), None);
    }

    #[test]
    fn inflate_reads_stored_streams() {
        let body = b"commit 172\0tree abc\n";
        assert_eq!(inflate_prefix(&zstore(body), 32), Some(body.to_vec()));
        assert_eq!(
            inflate_prefix(&zstore(body), 9),
            Some(b"commit 17".to_vec())
        );
        assert_eq!(inflate_prefix(b"not zlib", 32), None);
        assert_eq!(inflate_prefix(&[], 32), None);
        assert_eq!(inflate_prefix(&[0x78], 32), None);
        // FDICT set: refused.
        assert_eq!(inflate_prefix(&[0x78, 0x20, 0, 0, 0, 0], 32), None);
    }

    #[test]
    fn loose_header_grammar() {
        let ok = zstore(b"commit 172\0rest");
        assert!(loose_header_acceptable(&ok));
        let blob = zstore(b"blob 5000000000\0rest"); // blobs are not size-checked
        assert!(loose_header_acceptable(&blob));
        let bomb = zstore(b"commit 3221225472\0rest");
        assert!(!loose_header_acceptable(&bomb));
        let tree_edge = zstore(b"tree 16777216\0rest"); // exactly 16 MiB
        assert!(loose_header_acceptable(&tree_edge));
        let tag_over = zstore(b"tag 16777217\0rest");
        assert!(!loose_header_acceptable(&tag_over));
        assert!(!loose_header_acceptable(&zstore(b"exe 1\0")));
        assert!(!loose_header_acceptable(&zstore(b"commit \0")));
        assert!(!loose_header_acceptable(b"not zlib"));
        assert!(!loose_header_acceptable(&zstore(b"no-space\0")));
        let over_i64 = zstore(b"commit 9999999999999999999\0");
        assert!(!loose_header_acceptable(&over_i64));
    }
}
