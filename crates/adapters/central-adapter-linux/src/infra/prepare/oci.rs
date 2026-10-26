//! `oci.go` — the two-build equality proof. `CompareOCI` is a pure
//! function over two `OCIInventory` values; [`Comparator`] adapts it
//! to the service's port and records which comparator ran over which
//! ordered inventory.

use central_foundation::failure::Failure;
use central_infra::domain::{ComparisonFact, OciInventory, codes, inventory_digest};

/// `ComparatorVersion` — the comparison algorithm's identity, recorded
/// in the evidence. Bump whenever what [`compare_oci`] examines
/// changes, so a stored comparison fact stays interpretable.
pub const COMPARATOR_VERSION: &str = "central.oci-inventory-compare/v1";

/// `Comparator` — upstream `port.OCIComparator`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Comparator;

impl Comparator {
    /// `Compare` — refuses an incomplete first inventory, then runs
    /// the strict comparison and records the resulting fact.
    ///
    /// # Errors
    /// `OCI_INVENTORY_INVALID` when `a` carries no identity chain;
    /// `OCI_MISMATCH` when the inventories differ anywhere.
    pub fn compare(&self, a: &OciInventory, b: &OciInventory) -> Result<ComparisonFact, Failure> {
        if a.index_digest.is_empty() || a.manifest_digest.is_empty() || a.config_digest.is_empty() {
            return Err(Failure::invalid(
                codes::OCI_INVENTORY_INVALID,
                "dependencyprepare: first build produced an incomplete inventory",
            ));
        }
        compare_oci(a, b)?;
        Ok(ComparisonFact {
            comparator: COMPARATOR_VERSION.to_owned(),
            equal: true,
            index_digest: a.index_digest.clone(),
            inventory_digest: inventory_digest(a),
        })
    }
}

/// `CompareOCI` — strict, ordered equality of two OCI layouts: index
/// digest, manifest digest, config digest, layer count, then every
/// layer's digest, media type, size, and annotation set in order.
///
/// # Errors
/// `OCI_MISMATCH` with the first difference found.
pub fn compare_oci(a: &OciInventory, b: &OciInventory) -> Result<(), Failure> {
    let mismatch = |detail: String| {
        Failure::invalid(codes::OCI_MISMATCH, format!("dependencyprepare: {detail}"))
    };
    if a.index_digest != b.index_digest {
        return Err(mismatch(format!(
            "index digest {:?} != {:?}",
            a.index_digest, b.index_digest
        )));
    }
    if a.manifest_digest != b.manifest_digest {
        return Err(mismatch(format!(
            "manifest digest {:?} != {:?}",
            a.manifest_digest, b.manifest_digest
        )));
    }
    if a.config_digest != b.config_digest {
        return Err(mismatch(format!(
            "config digest {:?} != {:?}",
            a.config_digest, b.config_digest
        )));
    }
    if a.layers.len() != b.layers.len() {
        return Err(mismatch(format!(
            "layer count {} != {}",
            a.layers.len(),
            b.layers.len()
        )));
    }
    for (i, (la, lb)) in a.layers.iter().zip(&b.layers).enumerate() {
        if la.digest != lb.digest {
            return Err(mismatch(format!(
                "layer[{i}] digest {:?} != {:?}",
                la.digest, lb.digest
            )));
        }
        if la.media_type != lb.media_type {
            return Err(mismatch(format!(
                "layer[{i}] media type {:?} != {:?}",
                la.media_type, lb.media_type
            )));
        }
        if la.size != lb.size {
            return Err(mismatch(format!(
                "layer[{i}] size {} != {}",
                la.size, lb.size
            )));
        }
        if la.annotations.len() != lb.annotations.len() {
            return Err(mismatch(format!(
                "layer[{i}] annotation count {} != {}",
                la.annotations.len(),
                lb.annotations.len()
            )));
        }
        for (key, va) in &la.annotations {
            let Some(vb) = lb.annotations.get(key) else {
                return Err(mismatch(format!(
                    "layer[{i}] missing annotation key {key:?}"
                )));
            };
            if va != vb {
                return Err(mismatch(format!(
                    "layer[{i}] annotation {key:?} value {va:?} != {vb:?}"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_infra::domain::OciLayer;
    use std::collections::BTreeMap;

    fn digest(ch: char) -> String {
        format!("sha256:{}", ch.to_string().repeat(64))
    }

    fn inventory() -> OciInventory {
        OciInventory {
            index_digest: digest('a'),
            manifest_digest: digest('b'),
            config_digest: digest('c'),
            layers: vec![OciLayer {
                digest: digest('d'),
                media_type: "application/vnd.oci.image.layer.v1.tar".to_owned(),
                size: 42,
                annotations: BTreeMap::from([("k".to_owned(), "v".to_owned())]),
            }],
        }
    }

    // ---- oci_test.go ------------------------------------------------

    /// `TestCompareOCIRejectsDifferentIndexDigest`.
    #[test]
    fn compare_oci_rejects_different_index_digest() {
        let a = inventory();
        let mut b = inventory();
        b.index_digest = digest('z');
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
    }

    /// `TestCompareOCIRejectsDifferentManifestDigest`.
    #[test]
    fn compare_oci_rejects_different_manifest_digest() {
        let a = inventory();
        let mut b = inventory();
        b.manifest_digest = digest('z');
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
    }

    /// `TestCompareOCIRejectsDifferentConfigDigest`.
    #[test]
    fn compare_oci_rejects_different_config_digest() {
        let a = inventory();
        let mut b = inventory();
        b.config_digest = digest('z');
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
    }

    /// `TestCompareOCIAcceptsIdentical` + `TestComparatorRecordsFact`.
    #[test]
    fn compare_oci_accepts_identical() {
        let a = inventory();
        let b = inventory();
        compare_oci(&a, &b).expect("identical inventories compare equal");
        let fact = Comparator.compare(&a, &b).expect("comparator");
        assert_eq!(fact.comparator, COMPARATOR_VERSION);
        assert!(fact.equal);
        assert_eq!(fact.index_digest, a.index_digest);
        assert_eq!(fact.inventory_digest, inventory_digest(&a));
    }

    /// `TestCompareOCIRejectsDifferentLayerCount`.
    #[test]
    fn compare_oci_rejects_different_layer_count() {
        let a = inventory();
        let mut b = inventory();
        b.layers.clear();
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
    }

    /// `TestCompareOCIRejectsDifferentLayerDigest`.
    #[test]
    fn compare_oci_rejects_different_layer_digest() {
        let a = inventory();
        let mut b = inventory();
        b.layers[0].digest = digest('z');
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
    }

    /// `TestCompareOCIRejectsDifferentLayerMediaType`.
    #[test]
    fn compare_oci_rejects_different_layer_media_type() {
        let a = inventory();
        let mut b = inventory();
        b.layers[0].media_type = "other".to_owned();
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
    }

    /// `TestCompareOCIRejectsDifferentLayerSize`.
    #[test]
    fn compare_oci_rejects_different_layer_size() {
        let a = inventory();
        let mut b = inventory();
        b.layers[0].size += 1;
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
    }

    /// `TestCompareOCIRejectsDifferentLayerAnnotations` +
    /// `TestCompareOCIRejectsLayerAnnotationCountMismatch` +
    /// `TestCompareOCIRejectsMissingAnnotationKey`.
    #[test]
    fn compare_oci_rejects_different_layer_annotations() {
        let a = inventory();
        // Value differs.
        let mut b = inventory();
        b.layers[0]
            .annotations
            .insert("k".to_owned(), "other".to_owned());
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
        // Count differs.
        let mut b = inventory();
        b.layers[0]
            .annotations
            .insert("extra".to_owned(), "v".to_owned());
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
        // Key missing (same count, different key).
        let mut b = inventory();
        b.layers[0].annotations.clear();
        b.layers[0]
            .annotations
            .insert("other".to_owned(), "v".to_owned());
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
    }

    /// `TestCompareOCIRejectsDuplicateLayerOrder` — layer order is
    /// part of the identity; swapped layers are not the same image.
    #[test]
    fn compare_oci_rejects_layer_order_drift() {
        let mut a = inventory();
        a.layers.push(OciLayer {
            digest: digest('e'),
            media_type: "application/vnd.oci.image.layer.v1.tar".to_owned(),
            size: 1,
            annotations: BTreeMap::new(),
        });
        let mut b = a.clone();
        b.layers.swap(0, 1);
        assert_eq!(compare_oci(&a, &b).unwrap_err().code(), codes::OCI_MISMATCH);
    }

    /// `TestComparatorRejectsIncompleteFirstInventory` — an inventory
    /// with an empty identity chain is not evidence.
    #[test]
    fn comparator_rejects_incomplete_first_inventory() {
        let empty = OciInventory::default();
        let full = inventory();
        assert_eq!(
            Comparator.compare(&empty, &full).unwrap_err().code(),
            codes::OCI_INVENTORY_INVALID
        );
    }
}
