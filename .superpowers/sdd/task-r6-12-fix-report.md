# Task R6-T12 — Portable backup/restore review: fix report

Branch `r6-backup-restore-maintenance`, starting from `ec8f336`. The review
found two medium upstream-parity gaps in the portable bundle slice (tar
writer panic on ≥8GiB files; no fixture-level byte-parity proof), one
`strings.TrimPrefix` semantic drift, missing secret zeroization, and two
very-low cleanups. This report maps each finding to the commit that
resolves it.

## Commits

| Commit | Finding | Subject |
| ------ | ------- | ------- |
| `3011239` | MEDIUM-1 | PAX size/mtime records for octal overflow in tar writer |
| `faf9617` | MEDIUM-2 | committed Go byte-parity goldens for tar + bx1 |
| `32e9426` | LOW | strip exactly one `backup/` prefix like `strings.TrimPrefix` |
| `2eb6b88` | VERY LOW | remove staged `.import` config when chown fails |
| `338c497` | LOW | zeroize bundle-key material after use |

## MEDIUM-1 — `octal_field` panic on ≥8GiB files — `3011239`

`octal_field` formatted `format!("{value:0>width$o}")` into a stack buffer
and `copy_from_slice`d it into the header field; a 12-digit octal size
(≥8GiB) overflows the 11-usable-digit field and panicked. Fixed by
porting the rest of Go `archive/tar`'s `allowedFormats` decision tree the
writer already followed partially:

- `helper/portable.rs` — `write_header` now runs the Go voting pass:
  `verifyNumeric`/`verifyTime` mark USTAR unavailable when `size`,
  `mtime` (+ nanoseconds), or an out-of-range name cannot fit, then the
  surviving format writes the entry. Under PAX the overflowing value
  rides as a decimal `size=`/`mtime=` x-header record and the body
  header's numeric field takes Go `formatOctal`'s zero fallback —
  never a panic, never truncation.
- PAX records are emitted sorted (`mtime`, `path`, `size`) with Go's
  `formatPAXRecord` length arithmetic; far-future mtime (year 2300 test)
  gets the same treatment as oversized size.
- Three latent byte-parity divergences fixed in the same pass:
  `toASCII` drops non-ASCII runes outright (never `'?'`), `formatString`
  NULs the head of a trailing-slash run on overrun names, `writeRawFile`
  `TrimRight`s the literal `x` name after truncation, and
  `splitUSTARPath` gained Go's `i <= 0` refusal.
- Tests: `oversized_declared_size_emits_pax_size_record`,
  `far_future_mtime_emits_pax_mtime_record`,
  `ascii_and_slash_edge_semantics` — the first two assert the exact
  PAX record + zero-fallback body layout without materializing an 8GiB
  file (declared size / synthetic headers).

## MEDIUM-2 — fixture-level byte-parity proof — `faf9617`

Strongest option taken: **a real Go run** (not a recorded fallback).
`go1.26.8` was present; a generator test was added to the upstream repo
at `internal/portable/parity_gen_test.go` (source embedded below) which
ran `BuildTarGz`/`EncryptStream` over a fixed fixture and produced the
committed goldens.

Fixture `src/helper/testdata/portable-parity/fixture/` exercises:
nanosecond mtime, a >100-byte USTAR-splittable path, a >100-byte
unsplittable name, a non-ASCII path (`dïr/nâmé-€.txt`), and the
manifest/body mix. Goldens (decompressed tar bytes — deflate bodies
legitimately differ between Go `flate` and `miniz_oxide`, so parity is
asserted on the inflated stream):

| File | Bytes | SHA-256 |
| ---- | ----- | ------- |
| `parity-nano.tar` | 27136 | `0dc480c9…d6aca6e7` |
| `parity-second.tar` | 15872 | `fc3bc8e8…a5145bffe2` |
| `parity-big-head.tar` | 1536 | `339a220d…27eca62d6` |
| `parity-future-head.tar` | 1536 | `c73791a2…c4184d6` |
| `parity-bundle.bx1` | 1237 | `f316fac1…7c344c7a` |

Rust-side assertions in `helper/portable.rs`:

- `tar_bytes_match_upstream_nanosecond` / `_whole_second` — inflate
  `build_tar_gz` output, byte-compare against the goldens.
- `tar_head_bytes_match_upstream_overflow` — byte-compare the PAX
  headers for the 8GiB declared-size and year-2300 entries.
- `decrypts_upstream_produced_bundle` — `decrypt_stream` opens
  `parity-bundle.bx1` (upstream `EncryptStream`, key `[0x4b;32]`) and
  the inflated plaintext equals `parity-nano.tar`.
- Env-gated dumps (`DUMP_TARGZ_*`, `DUMP_BX1_*`) regenerate the Rust
  artifacts for the reverse direction.

Go-side results recorded from the harness run: upstream
`DecryptStream` opened the Rust-produced bx1 under the same key (`OK`),
and a sparse 8GiB `BuildTarGz` to `io.Discard` ran end-to-end (`OK`) —
the upstream writer emits the same PAX layout for real files that size.

### Golden generator (kept upstream, uncommitted scratch — source recorded here)

`go test ./internal/portable/ -run TestGenerateParityGoldens -count=1 -v`
with `PARITY_OUT`, `PARITY_FIXTURE`, and optionally `PARITY_RUST_BX1` /
`PARITY_RUST_TARGZ`; file SHA-256 `65033e45…dbc57c91`, 150 lines. It
writes the five goldens above, checks the reverse decrypt direction,
and runs the sparse-8GiB end-to-end proof against upstream `BuildTarGz`.
Full source (`internal/portable/parity_gen_test.go`):

```go
package portable_test

// Scratch golden generator for the central-rust R6-T12 byte-parity
// proof (helper/portable.rs). Run:
//
//	PARITY_OUT=<golden dir> PARITY_FIXTURE=<fixture dir> \
//	    go test ./internal/portable/ -run TestGenerateParityGoldens -count=1 -v
//
// Optional cross-direction check (a Rust-produced bx1 decrypts under
// upstream): also set PARITY_RUST_BX1=<path> PARITY_RUST_TARGZ=<path>.
//
// This file is generation scratch, not committed test coverage.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/enolalab/central/internal/portable"
)

func parityWrite(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d bytes)", name, len(data))
}

func parityGunzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGenerateParityGoldens(t *testing.T) {
	out := os.Getenv("PARITY_OUT")
	fixture := os.Getenv("PARITY_FIXTURE")
	if out == "" || fixture == "" {
		t.Skip("PARITY_OUT/PARITY_FIXTURE unset")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	nano := time.Date(2025, 3, 4, 5, 6, 7, 123456789, time.UTC)
	second := time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)

	// 1. Nanosecond created_at — every entry takes the PAX path.
	var nanoGz bytes.Buffer
	if err := portable.BuildTarGz(fixture, &nanoGz, nano); err != nil {
		t.Fatal(err)
	}
	nanoTar := parityGunzip(t, nanoGz.Bytes())
	parityWrite(t, out, "parity-nano.tar", nanoTar)

	// 2. Whole-second created_at — USTAR where it can encode, PAX
	// where it cannot.
	var secGz bytes.Buffer
	if err := portable.BuildTarGz(fixture, &secGz, second); err != nil {
		t.Fatal(err)
	}
	parityWrite(t, out, "parity-second.tar", parityGunzip(t, secGz.Bytes()))

	// 3. Declared 8GiB size — the exact header BuildTarGz writes for
	//    an overflowing file (WriteHeader emits headers only; the
	//    body stream is irrelevant to layout).
	var big bytes.Buffer
	tw := tar.NewWriter(&big)
	if err := tw.WriteHeader(&tar.Header{
		Name: "big.bin", Typeflag: tar.TypeReg, Mode: 0o600,
		Uid: 0, Gid: 0, Size: 8 << 30, ModTime: nano, Format: tar.FormatPAX,
	}); err != nil {
		t.Fatal(err)
	}
	parityWrite(t, out, "parity-big-head.tar", big.Bytes())

	// 4. Far-future mtime (year 2300) — octal overflow on ModTime.
	future := time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC)
	var fut bytes.Buffer
	tw = tar.NewWriter(&fut)
	if err := tw.WriteHeader(&tar.Header{
		Name: "future.bin", Typeflag: tar.TypeReg, Mode: 0o600,
		Uid: 0, Gid: 0, Size: 3, ModTime: future, Format: tar.FormatPAX,
	}); err != nil {
		t.Fatal(err)
	}
	parityWrite(t, out, "parity-future-head.tar", fut.Bytes())

	// 5. bx1 cross-check: upstream EncryptStream over the nano .tar.gz
	//    under a fixed key; the Rust side must decrypt to the same
	//    compressed payload.
	key := bytes.Repeat([]byte{0x4b}, 32)
	var bx1 bytes.Buffer
	if err := portable.EncryptStream(bytes.NewReader(nanoGz.Bytes()), &bx1, key); err != nil {
		t.Fatal(err)
	}
	parityWrite(t, out, "parity-bundle.bx1", bx1.Bytes())

	// 6. Reverse direction: decrypt a Rust-produced bx1 and compare
	//    against the Rust-produced .tar.gz it sealed.
	if rustBx1, rustGz := os.Getenv("PARITY_RUST_BX1"), os.Getenv("PARITY_RUST_TARGZ"); rustBx1 != "" && rustGz != "" {
		ct, err := os.ReadFile(rustBx1)
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(rustGz)
		if err != nil {
			t.Fatal(err)
		}
		var plain bytes.Buffer
		if err := portable.DecryptStream(bytes.NewReader(ct), &plain, key); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain.Bytes(), want) {
			t.Fatalf("rust bx1 plaintext mismatch: got %d want %d bytes", plain.Len(), len(want))
		}
		t.Logf("rust-produced bx1 decrypts under upstream DecryptStream: OK")
	}

	// 7. Full-scale proof: upstream BuildTarGz streams a real sparse
	//    8GiB entry without error (output discarded — layout already
	//    pinned by the head golden).
	sparseDir := t.TempDir()
	bigPath := filepath.Join(sparseDir, "big.bin")
	f, err := os.Create(bigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(8 << 30); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if err := portable.BuildTarGz(sparseDir, io.Discard, nano); err != nil {
		t.Fatal(err)
	}
	t.Logf("sparse 8GiB BuildTarGz to io.Discard: OK")
}
```

## LOW — `TrimPrefix` parity — `32e9426`

`import.rs` used `trim_start_matches("backup/")`, which strips every
repeated leading `backup/`; Go `strings.TrimPrefix` strips exactly one.
A manifest entry named `backup/backup/x` lost two levels in Rust and one
upstream. `strip_prefix("backup/").unwrap_or(&dump.path)` matches the
single-strip semantics; the `starts_with` gate two lines above keeps the
fallback unreachable but total.

## LOW — zeroization — `338c497`

The bx1 nonce is the DEK preimage (possession = decryption capability),
yet every intermediate sat un-scrubbed. Wrapped in `zeroize::Zeroizing`
(already a workspace dep; added to `central-infra`):

- `central-infra/src/portable.rs` — `hkdf_sha256`'s `prk`, chaining
  block `prev`, and the over-long `okm` tail; `derive_bundle_key`'s
  `okm` before the copy into the returned `[u8;32]`.
- `helper/export.rs` — the generated `nonce`, derived `key`, decoded
  `seed` + `seed_arr`, and the self-verify `decoded` nonce + `derived`
  key.
- `helper/import.rs` — the decoded token nonce and the derived bundle
  key feeding `decrypt_import_bundle`.
- `helper/portable.rs` — beyond-Go-parity hardening: the plaintext
  staging `buf` in `encrypt_stream` and each decrypted `opened` chunk
  in `decrypt_stream` are scrubbed on drop.

Deliberately left plain: the GCM *base* nonce inside `encrypt_stream`
(it is transmitted in the output header — not secret), `request
.trust_key_hex` (a public verifying-key pin — not secret), and test
material. `derive_bundle_key` still returns `[u8;32]` so callers opt
into `Zeroizing` without an API break.

## VERY LOW — staged `.import` cleanup — `2eb6b88`

Upstream `import.go:406-412` removes the staged `config.json.import`
when the chown half of `writeImportOwned` fails; Rust only removed it on
rename failure, leaving a root-owned staged file behind. Now removed on
either failure, matching upstream.

### `*_CEREMONY_REQUIRED` vocabulary — no change needed

The runtime reason strings already use upstream vocabulary everywhere
(`REASON_EXPORT_CEREMONY_REQUIRED`, `REASON_IMPORT_CEREMONY_REQUIRED`,
`REASON_{WIPE,DELETE,PRUNE,AUDIT}_CEREMONY_REQUIRED`). Remaining
"confirmer cannot perform" mentions are doc-comment prose, not wire
strings — nothing to rename, noted here for completeness.

## Verification

All run on the post-rebase HEAD (`338c497`):

- `cargo test -p central-adapter-linux --lib` — **806 passed, 0 failed**
- `cargo test -p central-infra` — **248 passed, 0 failed**
- `cargo fmt --all -- --check` — clean (two fmt leftovers folded into
  `3011239`/`faf9617`/`338c497` via autosquash rebase)
- `cargo check --workspace` — clean
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean
- `cargo deny check` — advisories/bans/licenses/sources ok (run because
  `central-infra/Cargo.toml` gained the pinned workspace `zeroize` dep;
  `Cargo.lock` updated in the same commit)
- Go harness `TestGenerateParityGoldens` — PASS (~35s): both decrypt
  directions verified, sparse 8GiB `BuildTarGz` end-to-end

## Notes / non-goals

- Parity proof used a **real Go run** — no `.superpowers/sdd/` recorded
  fallback was needed.
- The Go generator stays untracked in the upstream repo (generation
  scratch); this report records its source and digest for
  reproducibility.
- Unrelated untracked files (`.devin/`, `docs/implementation/
  roadmap-dashboard.html`, `scripts/roadmap-dashboard.*`) left alone.
- Remaining risk: parity is proven for the fixture's coverage matrix;
  paths not exercised (e.g. PAX on `uid`/`gid` fields, multibyte names
  at USTAR-split boundaries) follow the same ported decision tree but
  carry no golden. Adding them is a one-line fixture extension when
  wanted.
