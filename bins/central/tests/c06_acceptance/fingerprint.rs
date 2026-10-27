//! `internal/recovery/fingerprint.go` — the state fingerprint: what C06
//! scenario 1 captures before anything mutates, and what scenario 7 compares
//! the restored instance against. The comparison is arithmetic over what was
//! captured, so it lives in the portable half where every rule is exercised
//! on any workstation.

use std::collections::HashMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

/// `StreamedBodyFloorBytes` — the size at or above which an artifact body
/// fills a whole multipart part: the object-store adapter's staging part
/// size, imported rather than restated so the floor cannot drift.
pub const STREAMED_BODY_FLOOR_BYTES: i64 = central_adapter_s3::STAGING_PART_SIZE_BYTES as i64;

/// `EmptyItemSetDigest` — sha-256 of the empty string: the signature of a
/// capture query that matched nothing.
pub const EMPTY_ITEM_SET_DIGEST: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// `MaxReportedFingerprintDivergences` bounds a divergence report.
pub const MAX_REPORTED_FINGERPRINT_DIVERGENCES: usize = 12;

/// `SchemaRelation` — one relation: identity and pg_class relkind.
pub struct SchemaRelation {
    pub name: String,
    pub kind: String,
}

/// `SchemaObject` — one non-relation schema object.
pub struct SchemaObject {
    pub name: String,
    pub kind: String,
}

/// The relkinds the per-table capture covers.
fn fingerprinted_relation_kind(kind: &str) -> bool {
    matches!(kind, "r" | "p")
}

/// Relkinds covered elsewhere (index, partitioned index, TOAST, composite
/// type via the schema-object capture).
fn relation_kind_covered_elsewhere(kind: &str) -> bool {
    matches!(kind, "i" | "I" | "t" | "c")
}

/// `fingerprintedSchemaObjectKinds` — words, not catalog letters.
fn fingerprinted_schema_object_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function" | "procedure" | "enum type" | "domain" | "composite type"
    )
}

/// `RefuseUncoveredSchemaObjectKinds` — refuses a schema holding a
/// non-relation object of a kind the fingerprint does not capture.
pub fn refuse_uncovered_schema_object_kinds(objects: &[SchemaObject]) -> Result<(), String> {
    let mut uncovered = Vec::new();
    for object in objects {
        let kind = object.kind.trim();
        if kind.is_empty() {
            uncovered.push(format!("{} reports no object kind at all", object.name));
            continue;
        }
        if fingerprinted_schema_object_kind(kind) {
            continue;
        }
        uncovered.push(format!(
            "{} is a schema object of kind {kind:?}",
            object.name
        ));
    }
    if uncovered.is_empty() {
        return Ok(());
    }
    uncovered.sort();
    Err(format!(
        "recovery: the application's schema holds state this fingerprint does not capture, so a restore that lost it would compare equal:\n  - {}\nWiden the capture (and this refusal) before relying on a comparison against it",
        uncovered.join("\n  - ")
    ))
}

/// `RefuseUncoveredRelationKinds` — refuses a schema holding a relation of a
/// kind the fingerprint does not capture.
pub fn refuse_uncovered_relation_kinds(relations: &[SchemaRelation]) -> Result<(), String> {
    let mut uncovered = Vec::new();
    for relation in relations {
        let kind = relation.kind.trim();
        if kind.is_empty() {
            uncovered.push(format!("{} reports no relkind at all", relation.name));
            continue;
        }
        if fingerprinted_relation_kind(kind) || relation_kind_covered_elsewhere(kind) {
            continue;
        }
        uncovered.push(format!("{} is a relation of kind {kind:?}", relation.name));
    }
    if uncovered.is_empty() {
        return Ok(());
    }
    uncovered.sort();
    Err(format!(
        "recovery: the application's schema holds state this fingerprint does not capture, so a restore that lost it would compare equal:\n  - {}\nWiden the capture (and this refusal) before relying on a comparison against it",
        uncovered.join("\n  - ")
    ))
}

/// `TableFingerprint` — one relation: row count, order-independent content
/// digest, and the schema-object digest (columns, constraints, indexes,
/// triggers, policies, owner, ACLs).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TableFingerprint {
    pub name: String,
    pub row_count: i64,
    pub content_sha256: String,
    pub schema_sha256: String,
}

/// `ArtifactFingerprint` — one artifact: identity, body length and digest as
/// read back through the object store, and the metadata row digest.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ArtifactFingerprint {
    pub id: String,
    pub size_bytes: i64,
    pub body_sha256: String,
    /// `streamed` — a SIZE predicate (`size_bytes >= STREAMED_BODY_FLOOR_BYTES`),
    /// never an observation of streaming.
    pub streamed: bool,
    pub metadata_sha256: String,
}

/// `SchemaObjectFingerprint` — one non-relation schema object.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SchemaObjectFingerprint {
    pub name: String,
    pub kind: String,
    pub definition_sha256: String,
}

/// `StateFingerprint` — one instance's state, captured at one instant.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StateFingerprint {
    pub tables: Vec<TableFingerprint>,
    pub artifacts: Vec<ArtifactFingerprint>,
    pub schema_objects: Vec<SchemaObjectFingerprint>,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|b| {
            b.is_ascii_hexdigit()
                && !b.is_ascii_uppercase()
                && (b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

fn is_uuid_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let is_hyphen = matches!(index, 8 | 13 | 18 | 23);
        if is_hyphen {
            if *byte != b'-' {
                return false;
            }
        } else if !(byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)) {
            return false;
        }
    }
    true
}

/// The composite identity a schema object deduplicates under, escaped as the
/// digest escapes (final-review M-7).
fn schema_object_key(object: &SchemaObjectFingerprint) -> String {
    format!(
        "{}\t{}",
        digest_field(&object.kind),
        digest_field(&object.name)
    )
}

impl StateFingerprint {
    /// `Validate` — refuses a fingerprint that cannot evidence a restore.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_inner(true)
    }

    /// `ValidateAsCorrupted` — Validate for a capture OF A DAMAGED INSTANCE:
    /// the three corpus-liveness rules describe the corruption there.
    pub fn validate_as_corrupted(&self) -> Result<(), String> {
        self.validate_inner(false)
    }

    fn validate_inner(&self, require_live_corpus: bool) -> Result<(), String> {
        let mut problems: Vec<String> = Vec::new();
        if self.tables.is_empty() {
            problems.push(
                "it covers no table, so a restore that lost every row would compare equal"
                    .to_owned(),
            );
        }
        if self.artifacts.is_empty() {
            problems.push("it covers no artifact body, so a restore that lost every object would compare equal, and Slice C acceptance condition #9 would have no subject".to_owned());
        }
        let mut seen_table: HashMap<&str, usize> = HashMap::new();
        let mut total_rows: i64 = 0;
        for table in &self.tables {
            let name = table.name.trim();
            if name.is_empty() {
                problems.push("a table fingerprint carries no relation name".to_owned());
                continue;
            }
            *seen_table.entry(name).or_default() += 1;
            if seen_table[name] == 2 {
                problems.push(format!("{name} is fingerprinted more than once, so one of the two is unreachable in any comparison"));
            }
            if table.row_count < 0 {
                problems.push(format!("{name} reports a negative row count"));
            }
            total_rows += table.row_count;
            if !is_sha256(&table.content_sha256) {
                problems.push(format!(
                    "{name} carries a content digest that is not a sha-256"
                ));
            }
            if !is_sha256(&table.schema_sha256) {
                problems.push(format!("{name} carries a schema digest that is not a sha-256; without it the comparison is blind to a restore that returned every row and lost every index, key and constraint"));
            }
        }
        if require_live_corpus && !self.tables.is_empty() && total_rows == 0 {
            problems.push("every fingerprinted table is empty, so the corpus this was captured from was never seeded and the comparison would hold over an empty instance".to_owned());
        }
        let mut seen_artifact: HashMap<&str, usize> = HashMap::new();
        let mut streamed = 0usize;
        for artifact in &self.artifacts {
            if !is_uuid_shape(&artifact.id) {
                problems.push(
                    "an artifact fingerprint carries an identity that is not an opaque UUID"
                        .to_owned(),
                );
                continue;
            }
            *seen_artifact.entry(artifact.id.as_str()).or_default() += 1;
            if seen_artifact[artifact.id.as_str()] == 2 {
                problems.push("an artifact is fingerprinted more than once, so one of the two is unreachable in any comparison".to_owned());
            }
            if require_live_corpus && artifact.size_bytes <= 0 {
                problems.push("an artifact fingerprint reports an empty body; an empty body has the same digest whatever the store returns, so it cannot evidence a restored body".to_owned());
            }
            if !is_sha256(&artifact.body_sha256) {
                problems.push(
                    "an artifact fingerprint carries a body digest that is not a sha-256"
                        .to_owned(),
                );
            }
            if !is_sha256(&artifact.metadata_sha256) {
                problems.push(
                    "an artifact fingerprint carries a metadata digest that is not a sha-256"
                        .to_owned(),
                );
            }
            if artifact.streamed {
                streamed += 1;
                if artifact.size_bytes < STREAMED_BODY_FLOOR_BYTES {
                    problems.push(format!("an artifact is marked streamed at {} bytes, below the {STREAMED_BODY_FLOOR_BYTES}-byte multipart floor; the flag is a claim its own size contradicts", artifact.size_bytes));
                }
            } else if artifact.size_bytes >= STREAMED_BODY_FLOOR_BYTES {
                problems.push(format!("an artifact of {} bytes is not marked streamed although it reaches the {STREAMED_BODY_FLOOR_BYTES}-byte multipart floor; the flag is a claim its own size contradicts", artifact.size_bytes));
            }
        }
        let mut seen_object: HashMap<String, usize> = HashMap::new();
        for object in &self.schema_objects {
            let name = object.name.trim();
            let kind = object.kind.trim();
            if name.is_empty() {
                problems.push("a schema object fingerprint carries no object name".to_owned());
                continue;
            }
            if kind.is_empty() {
                problems.push(format!("schema object {name} carries no object kind, so the comparison cannot say what it is that changed"));
            }
            let key = format!("{}\t{}", digest_field(kind), digest_field(name));
            let occurrences = {
                let count = seen_object.entry(key).or_insert(0);
                *count += 1;
                *count
            };
            if occurrences == 2 {
                problems.push(format!("schema object {name} is fingerprinted more than once, so one of the two is unreachable in any comparison"));
            }
            if !is_sha256(&object.definition_sha256) {
                problems.push(format!("schema object {name} carries a definition digest that is not a sha-256; without it the comparison is blind to a restore that returned every table and lost the function bodies, enum labels and domain constraints the schema depends on"));
            }
        }
        if require_live_corpus && !self.artifacts.is_empty() && streamed == 0 {
            problems.push(format!("no fingerprinted body reaches the {STREAMED_BODY_FLOOR_BYTES}-byte multipart floor, so nothing here was streamed and Slice C acceptance condition #9 has no subject"));
        }
        if problems.is_empty() {
            return Ok(());
        }
        problems.sort();
        Err(format!(
            "recovery: this state fingerprint cannot evidence a restore:\n  - {}",
            problems.join("\n  - ")
        ))
    }

    /// `Digest` — the fingerprint's identity: one canonical record per table,
    /// artifact and schema object, in sorted order over every covered field.
    /// Every interpolated field goes through [`digest_field`] so a name
    /// containing a delimiter cannot compose the same bytes as two records.
    pub fn digest(&self) -> String {
        let mut hash = Sha256::new();
        for table in self.sorted_tables() {
            hash.update(
                format!(
                    "table\t{}\t{}\t{}\t{}\n",
                    digest_field(&table.name),
                    table.row_count,
                    table.content_sha256,
                    table.schema_sha256
                )
                .as_bytes(),
            );
        }
        for artifact in self.sorted_artifacts() {
            hash.update(
                format!(
                    "artifact\t{}\t{}\t{}\t{}\t{}\n",
                    digest_field(&artifact.id),
                    artifact.size_bytes,
                    artifact.streamed,
                    artifact.body_sha256,
                    artifact.metadata_sha256
                )
                .as_bytes(),
            );
        }
        for object in self.sorted_schema_objects() {
            hash.update(
                format!(
                    "schema object\t{}\t{}\t{}\n",
                    digest_field(&object.kind),
                    digest_field(&object.name),
                    object.definition_sha256
                )
                .as_bytes(),
            );
        }
        crate::hex_lower(hash.finalize())
    }

    /// `Equal`.
    pub fn equal(&self, other: &StateFingerprint) -> bool {
        self.digest() == other.digest()
    }

    /// `TotalRows`.
    pub fn total_rows(&self) -> i64 {
        self.tables.iter().map(|t| t.row_count).sum()
    }

    /// `TablesWithoutSchemaObjects` — relations whose schema digest is the
    /// digest of nothing at all (the schema axis anti-vacuity check).
    pub fn tables_without_schema_objects(&self) -> Vec<String> {
        let mut empty: Vec<String> = self
            .tables
            .iter()
            .filter(|t| t.schema_sha256 == EMPTY_ITEM_SET_DIGEST)
            .map(|t| t.name.clone())
            .collect();
        empty.sort();
        empty
    }

    /// `SchemaObjectsWithoutDefinition` — the same check on the other axis.
    pub fn schema_objects_without_definition(&self) -> Vec<String> {
        let mut empty: Vec<String> = self
            .schema_objects
            .iter()
            .filter(|o| o.definition_sha256 == EMPTY_ITEM_SET_DIGEST)
            .map(|o| o.name.clone())
            .collect();
        empty.sort();
        empty
    }

    /// `StreamedBodies` — fingerprinted bodies at or above the floor.
    pub fn streamed_bodies(&self) -> usize {
        self.artifacts.iter().filter(|a| a.streamed).count()
    }

    /// `SchemaObjectKinds`.
    pub fn schema_object_kinds(&self) -> HashMap<String, usize> {
        let mut kinds = HashMap::new();
        for object in &self.schema_objects {
            *kinds.entry(object.kind.clone()).or_default() += 1;
        }
        kinds
    }

    // The sorters order on EVERY field of their record, not the identity
    // alone (final-review M-7): a total order, so the digest never depends
    // on capture order.
    fn sorted_tables(&self) -> Vec<&TableFingerprint> {
        let mut sorted: Vec<&TableFingerprint> = self.tables.iter().collect();
        sorted.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.row_count.cmp(&b.row_count))
                .then(a.content_sha256.cmp(&b.content_sha256))
                .then(a.schema_sha256.cmp(&b.schema_sha256))
        });
        sorted
    }

    fn sorted_artifacts(&self) -> Vec<&ArtifactFingerprint> {
        let mut sorted: Vec<&ArtifactFingerprint> = self.artifacts.iter().collect();
        sorted.sort_by(|a, b| {
            a.id.cmp(&b.id)
                .then(a.size_bytes.cmp(&b.size_bytes))
                .then(b.streamed.cmp(&a.streamed))
                .then(a.body_sha256.cmp(&b.body_sha256))
                .then(a.metadata_sha256.cmp(&b.metadata_sha256))
        });
        sorted
    }

    fn sorted_schema_objects(&self) -> Vec<&SchemaObjectFingerprint> {
        let mut sorted: Vec<&SchemaObjectFingerprint> = self.schema_objects.iter().collect();
        sorted.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then(a.name.cmp(&b.name))
                .then(a.definition_sha256.cmp(&b.definition_sha256))
        });
        sorted
    }
}

/// `digestField` — escapes `\`, tab, newline, carriage return so a field
/// cannot supply its own record boundary. Identity on every ordinary name.
fn digest_field(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// `FingerprintDivergence` — the whole count, and a bounded ordered report.
#[derive(Debug, Default)]
pub struct FingerprintDivergence {
    pub count: usize,
    pub reported: Vec<String>,
}

impl FingerprintDivergence {
    pub fn empty(&self) -> bool {
        self.count == 0
    }
}

impl std::fmt::Display for FingerprintDivergence {
    /// `String` — locator-free, bounded, stating how much it did not report.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.count == 0 {
            return f.write_str("no divergence: the two fingerprints are the same state");
        }
        let report = self.reported.join("; ");
        if self.count > self.reported.len() {
            write!(
                f,
                "{} divergences, first {}: {report}",
                self.count,
                self.reported.len()
            )
        } else {
            write!(f, "{} divergences: {report}", self.count)
        }
    }
}

fn sorted_names<'a>(
    before: &'a HashMap<String, TableFingerprint>,
    after: &'a HashMap<String, TableFingerprint>,
) -> Vec<&'a String> {
    let mut names: Vec<&String> = before.keys().chain(after.keys()).collect();
    names.sort();
    names.dedup();
    names
}

/// `ContentDivergentTables` — tables whose ROWS differ (count or content
/// digest), and nothing else. Presence is not a row-level difference.
pub fn content_divergent_tables(
    before: &StateFingerprint,
    after: &StateFingerprint,
) -> Vec<String> {
    let before_tables: HashMap<String, TableFingerprint> = before
        .tables
        .iter()
        .map(|t| (t.name.clone(), t.clone()))
        .collect();
    let after_tables: HashMap<String, TableFingerprint> = after
        .tables
        .iter()
        .map(|t| (t.name.clone(), t.clone()))
        .collect();
    let mut names = Vec::new();
    for name in sorted_names(&before_tables, &after_tables) {
        let (Some(b), Some(a)) = (before_tables.get(name), after_tables.get(name)) else {
            continue;
        };
        if b.row_count != a.row_count || b.content_sha256 != a.content_sha256 {
            names.push(name.clone());
        }
    }
    names
}

/// `Divergences` — every way `after` differs from `before`.
pub fn divergences(before: &StateFingerprint, after: &StateFingerprint) -> FingerprintDivergence {
    divergences_inner(before, after, &std::collections::HashSet::new())
}

/// `DivergencesExceptContentOf` — row-level divergence of the named tables
/// withheld (schema digest still compared); artifacts and schema objects
/// untouched. Names are a measurement, never a hand-written exclusion list.
pub fn divergences_except_content_of(
    before: &StateFingerprint,
    after: &StateFingerprint,
    exempt: &[String],
) -> FingerprintDivergence {
    let exempt: std::collections::HashSet<String> = exempt.iter().cloned().collect();
    divergences_inner(before, after, &exempt)
}

fn divergences_inner(
    before: &StateFingerprint,
    after: &StateFingerprint,
    exempt_content_of: &std::collections::HashSet<String>,
) -> FingerprintDivergence {
    let mut found: Vec<String> = Vec::new();
    let before_tables: HashMap<String, &TableFingerprint> =
        before.tables.iter().map(|t| (t.name.clone(), t)).collect();
    let after_tables: HashMap<String, &TableFingerprint> =
        after.tables.iter().map(|t| (t.name.clone(), t)).collect();
    {
        let mut names: Vec<&String> = before_tables.keys().chain(after_tables.keys()).collect();
        names.sort();
        names.dedup();
        for name in names {
            let (in_before, in_after) = (before_tables.get(name), after_tables.get(name));
            match (in_before, in_after) {
                (Some(b), None) => {
                    found.push(format!(
                        "table {name} is absent after, and held {} rows before",
                        b.row_count
                    ));
                    continue;
                }
                (None, Some(a)) => {
                    found.push(format!(
                        "table {name} is present after and was absent before, holding {} rows",
                        a.row_count
                    ));
                    continue;
                }
                (Some(b), Some(a)) => {
                    if !exempt_content_of.contains(name.as_str()) {
                        if b.row_count != a.row_count {
                            found.push(format!(
                                "table {name} holds {} rows, want {}",
                                a.row_count, b.row_count
                            ));
                        }
                        if b.content_sha256 != a.content_sha256 {
                            found.push(format!(
                                "table {name} has different contents (its content digest differs)"
                            ));
                        }
                    }
                    if b.schema_sha256 != a.schema_sha256 {
                        found.push(format!("table {name} has a different schema (its column, constraint, index, trigger, policy, ownership and privilege digest differs)"));
                    }
                }
                _ => {}
            }
        }
    }
    let before_artifacts: HashMap<String, &ArtifactFingerprint> =
        before.artifacts.iter().map(|a| (a.id.clone(), a)).collect();
    let after_artifacts: HashMap<String, &ArtifactFingerprint> =
        after.artifacts.iter().map(|a| (a.id.clone(), a)).collect();
    {
        let mut names: Vec<&String> = before_artifacts
            .keys()
            .chain(after_artifacts.keys())
            .collect();
        names.sort();
        names.dedup();
        for name in names {
            match (before_artifacts.get(name), after_artifacts.get(name)) {
                (Some(b), None) => {
                    found.push(format!(
                        "artifact {name} is absent after, and held {} bytes before",
                        b.size_bytes
                    ));
                    continue;
                }
                (None, Some(a)) => {
                    found.push(format!(
                        "artifact {name} is present after and was absent before, holding {} bytes",
                        a.size_bytes
                    ));
                    continue;
                }
                (Some(b), Some(a)) => {
                    if b.size_bytes != a.size_bytes {
                        found.push(format!(
                            "artifact {name} holds {} bytes, want {}",
                            a.size_bytes, b.size_bytes
                        ));
                    }
                    if b.body_sha256 != a.body_sha256 {
                        found.push(format!(
                            "artifact {name} has a different body (its digest differs)"
                        ));
                    }
                    if b.streamed != a.streamed {
                        found.push(format!(
                            "artifact {name} changed streamed flag, now {}",
                            a.streamed
                        ));
                    }
                    if b.metadata_sha256 != a.metadata_sha256 {
                        found.push(format!("artifact {name} has different metadata (its metadata-row digest differs)"));
                    }
                }
                _ => {}
            }
        }
    }
    let before_objects: HashMap<String, &SchemaObjectFingerprint> = before
        .schema_objects
        .iter()
        .map(|o| (schema_object_key(o), o))
        .collect();
    let after_objects: HashMap<String, &SchemaObjectFingerprint> = after
        .schema_objects
        .iter()
        .map(|o| (schema_object_key(o), o))
        .collect();
    {
        let mut keys: Vec<&String> = before_objects.keys().chain(after_objects.keys()).collect();
        keys.sort();
        keys.dedup();
        for key in keys {
            match (before_objects.get(key), after_objects.get(key)) {
                (Some(b), None) => {
                    found.push(format!(
                        "schema object {} of kind {} is absent after",
                        b.name, b.kind
                    ));
                    continue;
                }
                (None, Some(a)) => {
                    found.push(format!(
                        "schema object {} of kind {} is present after and was absent before",
                        a.name, a.kind
                    ));
                    continue;
                }
                (Some(b), Some(a)) if b.definition_sha256 != a.definition_sha256 => {
                    found.push(format!("schema object {} of kind {} has a different definition (its digest differs)", a.name, a.kind));
                }
                _ => {}
            }
        }
    }
    let count = found.len();
    found.truncate(MAX_REPORTED_FINGERPRINT_DIVERGENCES);
    FingerprintDivergence {
        count,
        reported: found,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> String {
        crate::hex_lower(Sha256::digest([seed; 1]))
    }

    fn uuid(seed: usize) -> String {
        format!("00000000-0000-4000-8000-{seed:012x}")
    }

    fn live_fingerprint() -> StateFingerprint {
        StateFingerprint {
            tables: vec![TableFingerprint {
                name: "central.tasks".to_owned(),
                row_count: 3,
                content_sha256: digest(1),
                schema_sha256: digest(2),
            }],
            artifacts: vec![
                ArtifactFingerprint {
                    id: uuid(1),
                    size_bytes: 4096,
                    body_sha256: digest(3),
                    streamed: false,
                    metadata_sha256: digest(4),
                },
                ArtifactFingerprint {
                    id: uuid(2),
                    size_bytes: STREAMED_BODY_FLOOR_BYTES,
                    body_sha256: digest(5),
                    streamed: true,
                    metadata_sha256: digest(6),
                },
            ],
            schema_objects: vec![SchemaObjectFingerprint {
                name: "f()".to_owned(),
                kind: "function".to_owned(),
                definition_sha256: digest(7),
            }],
        }
    }

    #[test]
    fn a_vacuous_fingerprint_is_refused() {
        let err = StateFingerprint::default()
            .validate()
            .expect_err("must refuse");
        assert!(err.contains("covers no table"));
        assert!(err.contains("covers no artifact body"));
    }

    #[test]
    fn the_streamed_flag_must_agree_with_the_size() {
        let mut f = live_fingerprint();
        f.artifacts[0].streamed = true; // 4096 bytes, below the floor
        assert!(f.validate().unwrap_err().contains("below the"));
        let mut f = live_fingerprint();
        f.artifacts[1].streamed = false; // at the floor, unmarked
        assert!(f.validate().unwrap_err().contains("not marked streamed"));
    }

    #[test]
    fn a_corrupted_capture_keeps_shape_rules_but_not_corpus_liveness() {
        let mut f = live_fingerprint();
        f.artifacts[1].size_bytes = 0; // body destroyed — ValidateAsCorrupted keeps it
        f.artifacts[1].streamed = false;
        f.tables[0].row_count = 0;
        assert!(f.validate().is_err());
        f.validate_as_corrupted()
            .expect("corrupted capture validates");
    }

    #[test]
    fn the_digest_is_order_independent_and_covers_every_field() {
        let f = live_fingerprint();
        let mut reordered = StateFingerprint {
            tables: f.tables.clone(),
            artifacts: f.artifacts.clone(),
            schema_objects: f.schema_objects.clone(),
        };
        reordered.artifacts.reverse();
        assert!(f.equal(&reordered));
        let mut changed = live_fingerprint();
        changed.tables[0].schema_sha256 = digest(9);
        assert!(!f.equal(&changed));
    }

    #[test]
    fn divergences_reports_every_field_and_bounds_the_report() {
        let before = live_fingerprint();
        let mut after = live_fingerprint();
        after.tables[0].row_count = 2;
        after.artifacts[0].size_bytes = 8;
        let d = divergences(&before, &after);
        assert_eq!(d.count, 2);
        assert!(d.to_string().contains("2 divergences:"));
    }

    #[test]
    fn content_divergent_tables_names_only_row_level_differences() {
        let before = live_fingerprint();
        let mut after = live_fingerprint();
        after.tables[0].schema_sha256 = digest(9); // schema only — not content
        assert!(content_divergent_tables(&before, &after).is_empty());
        let mut after2 = live_fingerprint();
        after2.tables[0].row_count = 1;
        assert_eq!(
            content_divergent_tables(&before, &after2),
            vec!["central.tasks"]
        );
        // Exemption withholds row-level divergence but never schema.
        let d = divergences_except_content_of(&before, &after, &[]);
        assert_eq!(d.count, 1);
    }
}
