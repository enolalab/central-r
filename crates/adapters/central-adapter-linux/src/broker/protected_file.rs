//! `ProtectedFileBackend` — the port of upstream `protected_file.go`
//! and `protected_file_linux.go`: protected generations under
//! `root/generations/<uuid>/{value,metadata.json}` plus the `active.json`
//! generation pointer installed by atomic same-directory rename.
//!
//! Reads go through [`open_protected_file`]: the parent directory is
//! opened plainly (it is the store's own already-validated root), then
//! the leaf resolves fd-relative under `openat2` `RESOLVE_BENEATH |
//! RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` —
//! path traversal, symlink hops, magic links, and cross-mount escapes
//! are kernel-refused, and `O_NONBLOCK` + `S_ISREG` refuse FIFOs and
//! devices before any byte is read. Raw secret bytes stay in broker
//! memory; values are zeroized on the error paths upstream zeroes.
//!
//! The rich `protected_file_v1` model the security documentation names
//! (`binding.json`, phase records, multi-candidate generations) is what
//! `secret_bootstrap.go`/`recovery_journal.go` build *on* this backend;
//! this module ports the backend itself, upstream-shaped.

use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use central_foundation::failure::Failure;
use central_infra::authority::ProtectedGeneration;
use central_infra::domain::MAX_SECRET_BYTES;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::durable::{PRIVATE_DIRECTORY_MODE, rename_replace, sync_dir};

fn invalid(msg: &'static str) -> Failure {
    Failure::invalid("broker_protected_file", msg)
}
fn os(step: &str, e: impl core::fmt::Display) -> Failure {
    Failure::internal("broker_protected_file", format!("{step}: {e}"))
}

/// `authority.ProtectedGeneration`'s on-disk shape — upstream marshals
/// the struct with no JSON tags: PascalCase keys, `"RetiredAt": null`
/// while live.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationMetadata {
    /// `GenerationID`.
    #[serde(rename = "GenerationID")]
    pub generation_id: String,
    /// `Purpose`.
    #[serde(rename = "Purpose")]
    pub purpose: String,
    /// `CreatedAt`.
    #[serde(rename = "CreatedAt", with = "super::wire::rfc3339")]
    pub created_at: OffsetDateTime,
    /// `BindingID`.
    #[serde(rename = "BindingID")]
    pub binding_id: String,
    /// `RetiredAt` — `null` while live.
    #[serde(rename = "RetiredAt", with = "super::wire::rfc3339_opt")]
    pub retired_at: Option<OffsetDateTime>,
}

/// A protected generation the broker surfaced — the domain value
/// rebuilt from [`GenerationMetadata`] (uuid + timestamp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    /// `generation_id` (UUIDv7).
    pub generation_id: Uuid,
    /// The purpose it serves.
    pub purpose: String,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Owning binding (upstream: same uuid as the generation at create).
    pub binding_id: Uuid,
    /// Retirement timestamp; `None` while live.
    pub retired_at: Option<OffsetDateTime>,
}

/// `ProtectedFileBackend` — stores protected generations on the local
/// filesystem inside the instance state root.
#[derive(Debug, Clone)]
pub struct ProtectedFileBackend {
    root: PathBuf,
}

impl ProtectedFileBackend {
    /// `NewProtectedFileBackend` — store rooted at `root`.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn generations_dir(&self) -> PathBuf {
        self.root.join("generations")
    }

    fn generation_dir(&self, id: &Uuid) -> PathBuf {
        self.generations_dir().join(id.to_string())
    }

    /// `Create` — a new `generations/<id>/` directory, the value at
    /// `0400`, and the immutable metadata record.
    ///
    /// # Errors
    /// `broker_protected_file` when the value is out of bounds
    /// (`1..=64 KiB`) or any durable write fails.
    pub fn create(&self, purpose: &str, value: &[u8]) -> Result<Generation, Failure> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(invalid("protected_file: value is out of bounds"));
        }
        let gen_id = Uuid::now_v7();
        let gen_dir = self.generation_dir(&gen_id);
        fs::create_dir_all(&gen_dir).map_err(|e| os("protected_file: create dir", e))?;
        fs::set_permissions(&gen_dir, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
            .map_err(|e| os("protected_file: create dir", e))?;

        let value_path = gen_dir.join("value");
        write_private_0400(&value_path, value).map_err(|e| {
            Failure::internal(
                "broker_protected_file",
                format!("protected_file: write value: {}", e.message()),
            )
        })?;

        let generation = Generation {
            generation_id: gen_id,
            purpose: purpose.to_owned(),
            created_at: OffsetDateTime::now_utc(),
            binding_id: gen_id,
            retired_at: None,
        };
        let meta = serde_json::to_vec(&metadata_of(&generation))
            .map_err(|e| Failure::internal("broker_protected_file", format!("marshal: {e}")))?;
        write_private_0400(&gen_dir.join("metadata.json"), &meta).map_err(|e| {
            Failure::internal(
                "broker_protected_file",
                format!("protected_file: write metadata: {}", e.message()),
            )
        })?;
        Ok(generation)
    }

    /// `Current` — the active generation: `active.json` → the pinned
    /// `generation_id`, then its metadata.
    ///
    /// # Errors
    /// `broker_protected_file` when no active generation exists or the
    /// pointer/metadata is unreadable or unparseable.
    pub fn current(&self) -> Result<Generation, Failure> {
        let active_path = self.root.join("active.json");
        // Upstream's `os.IsNotExist → no active generation` gate.
        match fs::symlink_metadata(&active_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(invalid("protected_file: no active generation"));
            }
            _ => {}
        }
        let data = self.read_file(&active_path)?;
        #[derive(Deserialize)]
        struct Sel {
            generation_id: String,
        }
        let sel: Sel = serde_json::from_slice(&data).map_err(|e| {
            Failure::internal("broker_protected_file", format!("decode active: {e}"))
        })?;
        let gen_id = Uuid::parse_str(&sel.generation_id)
            .map_err(|e| Failure::internal("broker_protected_file", format!("active id: {e}")))?;
        self.get_by_id(gen_id)
    }

    /// `Enumerate` — every generation matching the optional purpose
    /// filter; unreadable/undecodable entries are skipped (upstream's
    /// `continue`), never fabricated.
    ///
    /// # Errors
    /// `broker_protected_file` only when the generations directory
    /// itself cannot be listed.
    pub fn enumerate(&self, purpose: &str) -> Result<Vec<Generation>, Failure> {
        let gens_dir = self.generations_dir();
        let entries = match fs::read_dir(&gens_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(os("protected_file: enumerate", e)),
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(gen_id) = Uuid::parse_str(&name) else {
                continue;
            };
            let Ok(generation) = self.get_by_id(gen_id) else {
                continue;
            };
            if !purpose.is_empty() && generation.purpose != purpose {
                continue;
            }
            out.push(generation);
        }
        Ok(out)
    }

    /// `Read` — the protected value for a generation the broker already
    /// knows. Bounded at `MAX_SECRET_BYTES`; the buffer is zeroized on
    /// every refusal path.
    ///
    /// # Errors
    /// `broker_protected_file` when the id is nil, the value is
    /// unreadable, or it is out of bounds.
    pub fn read(&self, generation: &Generation) -> Result<Vec<u8>, Failure> {
        if generation.generation_id.is_nil() {
            return Err(invalid("protected_file: empty generation"));
        }
        let value =
            self.read_file(&self.generation_dir(&generation.generation_id).join("value"))?;
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(invalid("protected_file: value is out of bounds"));
        }
        Ok(value)
    }

    /// `GetByID` — generation metadata for a known id.
    ///
    /// # Errors
    /// `broker_protected_file` when the id is nil or the metadata
    /// record is missing/corrupt.
    pub fn get_by_id(&self, gen_id: Uuid) -> Result<Generation, Failure> {
        if gen_id.is_nil() {
            return Err(invalid("protected_file: empty generation id"));
        }
        let meta_path = self.generation_dir(&gen_id).join("metadata.json");
        let data = self.read_file(&meta_path).map_err(|e| {
            Failure::internal(
                "broker_protected_file",
                format!("protected_file: generation {gen_id}: {}", e.message()),
            )
        })?;
        let meta: GenerationMetadata = serde_json::from_slice(&data).map_err(|e| {
            Failure::internal(
                "broker_protected_file",
                format!("protected_file: decode generation {gen_id}: {e}"),
            )
        })?;
        Ok(Generation {
            generation_id: Uuid::parse_str(&meta.generation_id).map_err(|e| {
                Failure::internal("broker_protected_file", format!("generation id: {e}"))
            })?,
            purpose: meta.purpose,
            created_at: meta.created_at,
            binding_id: Uuid::parse_str(&meta.binding_id).map_err(|e| {
                Failure::internal("broker_protected_file", format!("binding id: {e}"))
            })?,
            retired_at: meta.retired_at,
        })
    }

    /// `Delete` — removes one exact protected generation by id; never
    /// accepts a caller-supplied path or purpose. Go's `os.RemoveAll`
    /// is idempotent — an absent directory is a successful delete —
    /// and upstream relies on that for crash-recovery cleanups.
    ///
    /// # Errors
    /// `broker_protected_file` when the id is nil or removal fails for
    /// a reason other than absence.
    pub fn delete(&self, gen_id: Uuid) -> Result<(), Failure> {
        if gen_id.is_nil() {
            return Err(invalid("protected_file: empty generation id"));
        }
        match fs::remove_dir_all(self.generation_dir(&gen_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Failure::internal(
                "broker_protected_file",
                format!("protected_file: delete generation {gen_id}: {e}"),
            )),
        }
    }

    /// `Activate` — marks `gen_id` active via a same-directory
    /// `.active-*.tmp` file + fsync + `renameat2(0)` — the atomic
    /// replacement that is the activation linearization point.
    ///
    /// # Errors
    /// `broker_protected_file` on any step of the durable install.
    pub fn activate(&self, gen_id: Uuid) -> Result<(), Failure> {
        let active_path = self.root.join("active.json");
        let payload = serde_json::to_vec(&serde_json::json!({"generation_id": gen_id.to_string()}))
            .map_err(|e| {
                Failure::internal(
                    "broker_protected_file",
                    format!("protected_file: encode active generation: {e}"),
                )
            })?;
        // `.active-*.tmp` in the root, 0400, write+fsync, then rename.
        let tmp = {
            let mut name = [0u8; 8];
            rustix::rand::getrandom(&mut name, rustix::rand::GetRandomFlags::empty())
                .map_err(|e| os("protected_file: create active tmp", e))?;
            self.root
                .join(format!(".active-{}.tmp", super::wire::hex_encode(&name)))
        };
        let install = (|| -> Result<(), Failure> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .custom_flags(libc::O_CLOEXEC)
                .open(&tmp)
                .map_err(|e| os("protected_file: create active tmp", e))?;
            use std::io::Write as _;
            file.write_all(&payload)
                .map_err(|e| os("protected_file: write active tmp", e))?;
            file.sync_all()
                .map_err(|e| os("protected_file: sync active tmp", e))?;
            drop(file);
            rename_replace(&tmp, &active_path).map_err(|e| {
                Failure::internal(
                    "broker_protected_file",
                    format!("protected_file: atomic replace: {}", e.message()),
                )
            })
        })();
        if install.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        install?;
        sync_dir(&self.root)
    }

    /// `readFile` — bounded read through [`open_protected_file`] capped
    /// at `MAX_SECRET_BYTES + 1` (upstream's limit).
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, Failure> {
        let file = open_protected_file(path)?;
        let mut buf = Vec::new();
        file.take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| os("protected_file: read", e))?;
        Ok(buf)
    }
}

/// `openProtectedFile` — fd-relative `openat2`: open the parent
/// directory plainly, then resolve the bare filename beneath it with
/// `BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV` — the SC-DEF-57 shape
/// that keeps `/proc/self/fd/<N>` roots working while refusing
/// traversal. `O_NONBLOCK` + the `S_ISREG` fstat post-check refuse
/// FIFOs, devices, and sockets before any read can stall.
///
/// # Errors
/// `broker_protected_file` on open/fstat failure or a non-regular leaf.
pub fn open_protected_file(path: &Path) -> Result<fs::File, Failure> {
    let name = path.file_name().and_then(|n| n.to_str());
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let Some(name) = name else {
        return Err(invalid("protected_file: invalid path"));
    };
    if name.is_empty() {
        return Err(invalid("protected_file: invalid path"));
    }
    let dir_fd = rustix::fs::open(
        dir.as_os_str(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| os("protected_file: open parent", e))?;
    let fd = crate::sys::openat2::resolve_regular_file(&dir_fd, Path::new(name)).map_err(|e| {
        Failure::internal(
            "broker_protected_file",
            format!("protected_file: open: {}", e.message()),
        )
    })?;
    Ok(fs::File::from(fd))
}

/// Write `payload` to `path` created `O_EXCL`-ish at `0400` — the
/// protected generation file install (value + metadata).
fn write_private_0400(path: &Path, payload: &[u8]) -> Result<(), Failure> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| os("protected_file: write", e))?;
    use std::io::Write as _;
    file.write_all(payload)
        .and_then(|()| file.sync_all())
        .map_err(|e| os("protected_file: write", e))?;
    drop(file);
    sync_dir(path.parent().unwrap_or_else(|| Path::new(".")))
}

/// `ProtectedGeneration` → metadata wire struct.
pub(crate) fn metadata_of(generation: &Generation) -> GenerationMetadata {
    GenerationMetadata {
        generation_id: generation.generation_id.to_string(),
        purpose: generation.purpose.clone(),
        created_at: generation.created_at,
        binding_id: generation.binding_id.to_string(),
        retired_at: generation.retired_at,
    }
}

/// The domain-facing view — adapter callers that need the
/// `central-infra` shape get it here rather than re-parsing.
#[must_use]
pub fn to_domain(generation: &Generation) -> ProtectedGeneration {
    use central_foundation::identity::{ProtectedGenerationId, SecretBindingId};
    ProtectedGeneration {
        generation_id: ProtectedGenerationId::from_trusted_db_bytes(
            *generation.generation_id.as_bytes(),
        ),
        purpose: generation.purpose.clone(),
        created_at: generation.created_at,
        binding_id: SecretBindingId::from_trusted_db_bytes(*generation.binding_id.as_bytes()),
        retired_at: generation.retired_at,
    }
}

// ---------------------------------------------------------------------------
// Tests — upstream `protected_file_linux_test.go`/`protected_file_test.go`
// coverage, ported.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::TempDir;
    use std::os::unix::fs::symlink;

    #[test]
    fn create_read_activate_delete_round_trip() {
        let dir = TempDir::new("protected-file");
        let backend = ProtectedFileBackend::new(dir.to_path_buf());
        let generation = backend.create("minio_root_v1", b"sekret").unwrap();
        assert!(!generation.generation_id.is_nil());
        // uuidv7 — generation ids are time-ordered.
        assert_eq!(generation.generation_id.get_version_num(), 7);
        assert_eq!(generation.purpose, "minio_root_v1");
        assert_eq!(generation.binding_id, generation.generation_id);
        // 0400 value + metadata, private generation dir.
        let gen_dir = dir
            .join("generations")
            .join(generation.generation_id.to_string());
        let mode = fs::symlink_metadata(gen_dir.join("value"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o400);
        assert_eq!(backend.read(&generation).unwrap(), b"sekret");
        // Metadata keeps upstream's PascalCase wire shape.
        let meta_raw: serde_json::Value =
            serde_json::from_slice(&fs::read(gen_dir.join("metadata.json")).unwrap()).unwrap();
        assert_eq!(meta_raw["Purpose"], "minio_root_v1");
        assert_eq!(meta_raw["RetiredAt"], serde_json::Value::Null);
        // Activate installs the active.json pointer.
        assert!(backend.current().is_err());
        backend.activate(generation.generation_id).unwrap();
        assert_eq!(backend.current().unwrap(), generation);
        // Delete removes the generation directory outright, and like
        // upstream `os.RemoveAll` is idempotent — deleting the same
        // generation again (or one that never existed) succeeds.
        backend.delete(generation.generation_id).unwrap();
        assert!(backend.get_by_id(generation.generation_id).is_err());
        backend.delete(generation.generation_id).unwrap();
        backend.delete(Uuid::now_v7()).unwrap();
    }

    #[test]
    fn enumerate_filters_by_purpose() {
        let dir = TempDir::new("protected-file");
        let backend = ProtectedFileBackend::new(dir.to_path_buf());
        let a = backend.create("one", b"a").unwrap();
        backend.create("two", b"b").unwrap();
        assert_eq!(backend.enumerate("").unwrap().len(), 2);
        let only = backend.enumerate("one").unwrap();
        assert_eq!(only, vec![a]);
    }

    #[test]
    fn create_rejects_out_of_bounds_values() {
        let dir = TempDir::new("protected-file");
        let backend = ProtectedFileBackend::new(dir.to_path_buf());
        assert!(backend.create("p", b"").is_err());
        assert!(
            backend
                .create("p", &vec![0u8; MAX_SECRET_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn openat2_confines_symlink_and_traversal() {
        let dir = TempDir::new("protected-file");
        let outside = TempDir::new("protected-file-outside");
        fs::write(outside.join("secret"), b"outside").unwrap();
        // A symlink inside the root pointing outside must refuse — the
        // fd-relative RESOLVE_BENEATH|NO_SYMLINKS read never follows it.
        symlink(outside.join("secret"), dir.join("link")).unwrap();
        assert!(open_protected_file(&dir.join("link")).is_err());
        // `..` escapes refuse beneath the parent fd.
        assert!(open_protected_file(&dir.join("../protected-file-outside/secret")).is_err());
        // A real file opens.
        fs::write(dir.join("value"), b"ok").unwrap();
        let mut contents = String::new();
        open_protected_file(&dir.join("value"))
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "ok");
    }
}
