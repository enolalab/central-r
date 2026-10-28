//! Shared test fixtures for the release verify / import / export tests:
//! a VALID signed release tree built under a lock whose infra pins were set
//! to the test tarball (the lock's digest is its raw-byte hash, so the
//! clone keeps the genuine `lock_digest`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use central_infra::domain::{OciInventory, REQUIRED_ATTESTATION_PREDICATES};
use central_infra::prepare::{
    AttestationTrustPolicy, Lock, RELEASE_INFRA_MODES, ReleasePaths, TrustedKey,
    envelope_file_name, new_attestation_statement, release_trust_materials, subject_from_inventory,
};
use sha2::{Digest as _, Sha256};

use super::attestation::{AttestationSigner, AttestationVerifier};
use super::release_stage::{read_release_minio_inventory, stage_release_dir};
use super::{Comparator, LockAdapter, OpDeadline};

pub(crate) fn hex(data: &[u8]) -> String {
    super::hex_lower(&Sha256::digest(data))
}

pub(crate) fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "central-pp-rel-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

pub(crate) fn write_tar(path: &Path, files: &BTreeMap<String, Vec<u8>>) {
    let mut builder = tar::Builder::new(std::fs::File::create(path).expect("tar"));
    for (name, body) in files {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(body.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        builder
            .append_data(&mut header, name, body.as_slice())
            .expect("member");
    }
    builder.finish().expect("finish");
}

pub(crate) fn write_minio_tar(dir: &Path) {
    let config = br#"{"architecture":"amd64","os":"linux","marker":"m"}"#.to_vec();
    let config_hex = hex(&config);
    let layer = b"layer-m".to_vec();
    let layer_hex = hex(&layer);
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{config_hex}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{layer_hex}","size":{}}}]}}"#,
        config.len(),
        layer.len()
    )
    .into_bytes();
    let manifest_hex = hex(&manifest);
    let index = format!(
        r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{manifest_hex}","size":{}}}]}}"#,
        manifest.len()
    )
    .into_bytes();
    std::fs::create_dir_all(dir.join("minio")).expect("minio dir");
    write_tar(
        &dir.join("minio").join("image.tar"),
        &BTreeMap::from([
            ("index.json".to_owned(), index),
            (
                "oci-layout".to_owned(),
                br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec(),
            ),
            (format!("blobs/sha256/{manifest_hex}"), manifest),
            (format!("blobs/sha256/{config_hex}"), config),
            (format!("blobs/sha256/{layer_hex}"), layer),
        ]),
    );
}

/// Returns the sha256 of the infra tarball's config blob.
pub(crate) fn write_infra_tar(dir: &Path) -> String {
    let config = br#"{"architecture":"amd64","os":"linux","marker":"i"}"#.to_vec();
    let config_hex = hex(&config);
    let config_name = format!("{config_hex}.json");
    let manifest = format!(
        r#"[{{"Config":{config_name:?},"RepoTags":["infra:t"],"Layers":["l/layer.tar"]}}]"#
    )
    .into_bytes();
    std::fs::create_dir_all(dir.join("infra")).expect("infra dir");
    write_tar(
        &dir.join("infra").join("image.tar"),
        &BTreeMap::from([
            ("manifest.json".to_owned(), manifest),
            (config_name, config),
            ("l/layer.tar".to_owned(), b"layer-i".to_vec()),
        ]),
    );
    format!("sha256:{config_hex}")
}

pub(crate) fn signer() -> AttestationSigner {
    let seed = [9u8; 32];
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut private = seed.to_vec();
    private.extend_from_slice(&key.verifying_key().to_bytes());
    AttestationSigner::from_private_key("rel-key", &private).expect("signer")
}

pub(crate) fn policy(signer: &AttestationSigner) -> AttestationTrustPolicy {
    AttestationTrustPolicy {
        keys: vec![TrustedKey {
            key_id: signer.key_id().to_owned(),
            public_key: signer.public_key_hex(),
            expires_at: None,
            revoked: false,
        }],
    }
}

pub(crate) struct Release {
    pub(crate) dir: PathBuf,
    pub(crate) lock: Lock,
    pub(crate) infra_manifest: String,
    pub(crate) verifier: AttestationVerifier,
    pub(crate) inventory: OciInventory,
    pub(crate) signer: AttestationSigner,
}

impl Drop for Release {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A VALID release under `dir` for a lock whose infra pins were set to
/// the test tarball (the lock's digest is its raw-byte hash, so the
/// clone keeps the genuine `lock_digest`).
pub(crate) fn release(tag: &str) -> Release {
    let dir = tmp(tag);
    write_minio_tar(&dir);
    let infra_config = write_infra_tar(&dir);
    let infra_manifest = format!("sha256:{}", "e".repeat(64));
    let mut lock = LockAdapter::new().expect("lock").lock().clone();
    for locked in &mut lock.modes {
        if RELEASE_INFRA_MODES.contains(&locked.mode) {
            locked.inventory.config_digest.clone_from(&infra_config);
            locked.inventory.manifest_digest.clone_from(&infra_manifest);
        }
    }
    let trust = release_trust_materials(&lock).expect("trust");
    std::fs::write(
        dir.join("release.json"),
        format!(
            r#"{{"schema_version":"central.release/v1","lock_digest":"{}"}}"#,
            trust.lock_digest
        ),
    )
    .expect("release.json");
    let inventory = read_release_minio_inventory(&dir.join("minio").join("image.tar"), &dir)
        .expect("inventory");
    let subject = subject_from_inventory("minio", &inventory);
    let mut materials = trust;
    materials.builder_identity_a = "sha256:builder-a".to_owned();
    materials.builder_identity_b = "sha256:builder-b".to_owned();
    materials.invocation_digest = "sha256:invocation".to_owned();
    materials.operation_id = "prepare-producer".to_owned();
    let signer = signer();
    for predicate in REQUIRED_ATTESTATION_PREDICATES {
        let statement =
            new_attestation_statement(predicate, subject.clone(), materials.clone()).expect("stmt");
        std::fs::write(
            dir.join("minio").join(envelope_file_name(predicate)),
            signer.sign(&statement).expect("sign").envelope,
        )
        .expect("envelope");
    }
    let comparison = Comparator.compare(&inventory, &inventory).expect("cmp");
    std::fs::write(
        dir.join("minio").join("comparison.json"),
        serde_json::to_vec(&comparison).expect("json"),
    )
    .expect("comparison");
    let verifier = AttestationVerifier::new(policy(&signer));
    Release {
        dir,
        lock,
        infra_manifest,
        verifier,
        inventory,
        signer,
    }
}

pub(crate) fn stage(r: &Release) -> (ReleasePaths, PathBuf) {
    let work = tmp("work");
    (
        stage_release_dir(OpDeadline::NONE, &r.dir, &work).expect("stage"),
        work,
    )
}
