//! `cmd/central/c06_scenario78_equivalence_profile_test.go` — C06 scenarios 7
//! and 8: the state-equivalence comparison and the minimum-profile
//! measurements, ported with the discrimination battery that proves the
//! comparison discriminates.
//!
//! Scenario 7 compares the live instance to the PRE-CORRUPTION fingerprint
//! scenario 1 recorded — never a fresh capture, which would describe the
//! state after everything this run did. The comparison itself is then shown
//! to discriminate: a battery of one-axis-at-a-time perturbations, each held
//! to an exact expected divergence report, each reverted, and each held to
//! the axes the comparison's own attribution assigns it.
//!
//! Scenario 8 checks the five minimum-profile measurements. Three are read
//! from the shared record set (taken by s1 and s5); two are measured here —
//! the repository's byte count walked over regular files only, and the
//! device floor measured through the PRODUCTION capacity source, per device
//! and never aggregated.
//!
//! SC-DEF-83 is kept: the restore-audit relations
//! (recovery_operations, recovery_quarantines,
//! recovery_bootstrap_registrations) leave both sides of the
//! moved-equals-footprint equality and join the row-level content
//! exemption — schema, presence and every other axis stay compared.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use sha2::Digest as _;
use uuid::Uuid;

use central_artifact::port::ObjectStore as _;

use crate::evidence;
use crate::fingerprint::{self, ArtifactFingerprint, STREAMED_BODY_FLOOR_BYTES, StateFingerprint};
use crate::profile::{self, MEASUREMENT_FIELDS, MeasurementField};
use crate::runner::runner;
use crate::scenario2::{self, Bind, CorruptionKit, ScenarioLog, connect_pg, ready_artifact_rows};
use crate::slice_c::{self};

// ---------------------------------------------------------------------------
// The scope disclosures.
// ---------------------------------------------------------------------------

/// `c06Scenario7ScopeDisclosure` — carried on the log of every comparison
/// this scenario makes.
pub(crate) const SCENARIO7_SCOPE_DISCLOSURE: &str = "SCOPE: the equality this scenario reports is against the pre-corruption fingerprint scenario 1 captured of the LIVE instance, not against a sealed backup manifest -- no backup can be sealed on any host while the production composition supplies no throughput gate, so a pass here says the instance still carries what the fingerprint recorded, not that a restore reproduced it. The comparison is proven to discriminate by perturbing the instance it just called equal, one axis at a time, and requiring each change to be reported by name and by nothing else; a comparison that returned 'no divergence' for every change would pass the control and establish nothing. The perturbations act on synthetic probe objects/relations plus the corpus scenario 2 seeded, through the same two stores the capture reads, and every one is reverted with the instance required to compare equal again before the battery ends. The perturbation SQL runs through the test's own connection with the same privilege the migration DSN carries -- it is an operator-level write, not a peer write through the broker, and the disclosure stands for that.";

/// `c06Scenario8ScopeDisclosure`.
pub(crate) const SCENARIO8_SCOPE_DISCLOSURE: &str = "SCOPE: the device floor below is measured through the production capacity source per device, never aggregated -- free space summed across filesystems is a number no admission decision is ever made from. The repository byte count is a walk of regular files under the repository root; directories and links are excluded because their sizes are filesystem bookkeeping, not repository content. The backup rate, restore rate and restore elapsed readings are READ from the shared record set, never recomputed: each is attributed to the entry that measured it, and an absent reading is reported as that entry's defect rather than checked against its bound -- two of the five bounds are upper bounds that a zero satisfies, so an absent reading must not pass as a met assertion.";

// ---------------------------------------------------------------------------
// The equivalence-axis vocabulary.
// ---------------------------------------------------------------------------

/// `c06EquivalenceAxis` — one reportable axis of the state comparison.
/// The vocabulary is derived from the fingerprint structs' serde field
/// names by `axes_the_comparison_can_report`, never by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum EquivalenceAxis {
    TableRowCount,
    TableContent,
    TableSchema,
    TablePresence,
    ArtifactSize,
    ArtifactBody,
    ArtifactStreamed,
    ArtifactMetadata,
    ArtifactPresence,
    SchemaObjectDefn,
    SchemaObjectPresence,
}

impl EquivalenceAxis {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::TableRowCount => "tables[].row_count",
            Self::TableContent => "tables[].content_sha256",
            Self::TableSchema => "tables[].schema_sha256",
            Self::TablePresence => "tables[]",
            Self::ArtifactSize => "artifacts[].size_bytes",
            Self::ArtifactBody => "artifacts[].body_sha256",
            Self::ArtifactStreamed => "artifacts[].streamed",
            Self::ArtifactMetadata => "artifacts[].metadata_sha256",
            Self::ArtifactPresence => "artifacts[]",
            Self::SchemaObjectDefn => "schema_objects[].definition_sha256",
            Self::SchemaObjectPresence => "schema_objects[]",
        }
    }
}

/// `c06AxesTheComparisonCanReport` — derives every axis the comparison can
/// report from the fingerprint structs themselves (one per serde-tagged
/// non-identity field, plus one presence axis per collection). The identity
/// fields are covered by presence: tables identify by `name`, artifacts by
/// `id`, schema objects by `kind` + `name`.
pub(crate) fn axes_the_comparison_can_report() -> BTreeSet<EquivalenceAxis> {
    // Derivation is structural rather than hand-written: the serde keys of
    // each fingerprint struct are enumerated and every non-identity key
    // must resolve to an axis. A field added to a struct and not to the
    // axis vocabulary surfaces here as an unmapped serde key — loud, not
    // silently uncovered.
    let mut derived = BTreeSet::new();
    let mut unmapped = Vec::new();
    let table_keys = serde_keys(&fingerprint::TableFingerprint {
        name: String::new(),
        row_count: 0,
        content_sha256: String::new(),
        schema_sha256: String::new(),
    });
    for key in table_keys {
        match key.as_str() {
            "name" => {} // identity — covered by presence
            "row_count" => {
                derived.insert(EquivalenceAxis::TableRowCount);
            }
            "content_sha256" => {
                derived.insert(EquivalenceAxis::TableContent);
            }
            "schema_sha256" => {
                derived.insert(EquivalenceAxis::TableSchema);
            }
            other => unmapped.push(format!("tables[].{other}")),
        }
    }
    derived.insert(EquivalenceAxis::TablePresence);
    let artifact_keys = serde_keys(&ArtifactFingerprint {
        id: String::new(),
        size_bytes: 0,
        body_sha256: String::new(),
        streamed: false,
        metadata_sha256: String::new(),
    });
    for key in artifact_keys {
        match key.as_str() {
            "id" => {}
            "size_bytes" => {
                derived.insert(EquivalenceAxis::ArtifactSize);
            }
            "body_sha256" => {
                derived.insert(EquivalenceAxis::ArtifactBody);
            }
            "streamed" => {
                derived.insert(EquivalenceAxis::ArtifactStreamed);
            }
            "metadata_sha256" => {
                derived.insert(EquivalenceAxis::ArtifactMetadata);
            }
            other => unmapped.push(format!("artifacts[].{other}")),
        }
    }
    derived.insert(EquivalenceAxis::ArtifactPresence);
    let object_keys = serde_keys(&fingerprint::SchemaObjectFingerprint {
        name: String::new(),
        kind: String::new(),
        definition_sha256: String::new(),
    });
    for key in object_keys {
        match key.as_str() {
            "name" | "kind" => {}
            "definition_sha256" => {
                derived.insert(EquivalenceAxis::SchemaObjectDefn);
            }
            other => unmapped.push(format!("schema_objects[].{other}")),
        }
    }
    derived.insert(EquivalenceAxis::SchemaObjectPresence);
    debug_assert!(
        unmapped.is_empty(),
        "the fingerprint structs gained fields the axis vocabulary does not name: {unmapped:?}"
    );
    derived
}

/// The serde field names of a fingerprint struct — the Rust stand-in for
/// upstream's `reflect`-over-json-tags derivation.
fn serde_keys<T: serde::Serialize>(value: &T) -> Vec<String> {
    let serde_json::Value::Object(map) =
        serde_json::to_value(value).expect("a fingerprint struct serializes to an object")
    else {
        panic!("a fingerprint struct serializes to an object")
    };
    let mut keys: Vec<String> = map.keys().cloned().collect();
    keys.sort();
    keys
}

fn sorted_axes(axes: &BTreeSet<EquivalenceAxis>) -> Vec<EquivalenceAxis> {
    axes.iter().copied().collect()
}

fn axis_set(axes: &[EquivalenceAxis]) -> BTreeSet<EquivalenceAxis> {
    axes.iter().copied().collect()
}

// ---------------------------------------------------------------------------
// The corpus the perturbation table acts on — recovered from the instance,
// never re-seeded (upstream's c06CorpusFromFingerprint).
// ---------------------------------------------------------------------------

/// `c06SeededArtifact` — one corpus artifact's handles: identity, ready
/// key, and the size/digest/streamed triple the fingerprint itself
/// recorded (the battery's expectations read these, never the body).
struct SeededArtifact {
    id: String,
    ready_key: String,
    size: i64,
    digest: [u8; 32],
    streamed: bool,
}

/// `c06Corpus` — the task/workspace handles plus every fingerprinted
/// artifact, recovered from the instance so this scenario stays a reader
/// of the state rather than a second writer of it.
struct Corpus {
    task_id: String,
    workspace_id: String,
    artifacts: Vec<SeededArtifact>,
}

/// `c06CorpusFromFingerprint` — recover the corpus handles from the live
/// instance, with each artifact's store answer checked against the size
/// the fingerprint recorded (the drift check is a stat, not a body read —
/// the 1.5 GiB streamed subject must not land in RAM here).
fn corpus_from_fingerprint(
    conn: &central_adapter_postgres::store_support::BlockingConn,
    kit: &CorruptionKit,
    fingerprint: &StateFingerprint,
) -> Result<Corpus, String> {
    let (task_id, workspace_id): (String, String) = conn
        .run(|c| {
            Box::pin(async move {
                sqlx::query_as(
                    "SELECT t.id::text, t.workspace_id::text FROM central.tasks t
                     JOIN central.artifacts a ON a.task_id = t.id
                     WHERE a.state = 'ready' AND a.delete_intent_at IS NULL
                     ORDER BY t.id LIMIT 1",
                )
                .fetch_one(&mut *c)
                .await
                .map_err(|e| {
                    central_foundation::failure::Failure::internal(
                        "c06",
                        format!("recover the task the seeded corpus hangs off: {e}"),
                    )
                })
            })
        })
        .map_err(|e| e.to_string())?;

    let rows = ready_artifact_rows(conn)?;
    let mut ready_keys = HashMap::new();
    for row in &rows {
        ready_keys.insert(row.id.clone(), row.ready_key.clone());
    }
    let mut corpus = Corpus {
        task_id,
        workspace_id,
        artifacts: Vec::new(),
    };
    for artifact in &fingerprint.artifacts {
        let ready_key = ready_keys
            .get(&artifact.id)
            .cloned()
            .ok_or_else(|| format!("recover the ready key of artifact {}", artifact.id))?;
        // The drift check opens the stream, reads the store's answer
        // (size), and closes without reading the body — the stat the
        // production store offers through the same path the fingerprint
        // reads bodies.
        let (stream, info) = kit
            .runtime
            .block_on(kit.store.read(central_artifact::port::ObjectRef {
                key: ready_key.clone(),
            }))
            .map_err(|e| format!("stat artifact {} before the battery: {e}", artifact.id))?;
        let mut stream = stream;
        kit.runtime
            .block_on(stream.close())
            .map_err(|e| format!("close the stat stream of artifact {}: {e}", artifact.id))?;
        if info.size != artifact.size_bytes {
            return Err(format!(
                "artifact {} stats as {} bytes and the base fingerprint records {}; the instance has drifted from the fingerprint this battery is about to perturb against",
                artifact.id, info.size, artifact.size_bytes
            ));
        }
        let raw_digest = decode_hex_32(&artifact.body_sha256).ok_or_else(|| {
            format!(
                "artifact {} carries body digest {:?}, not a sha-256",
                artifact.id, artifact.body_sha256
            )
        })?;
        corpus.artifacts.push(SeededArtifact {
            id: artifact.id.clone(),
            ready_key,
            size: artifact.size_bytes,
            digest: raw_digest,
            streamed: artifact.streamed,
        });
    }
    if corpus.artifacts.is_empty() {
        return Err(
            "the base fingerprint covers no artifact, so the perturbation table has no body to act on"
                .to_owned(),
        );
    }
    Ok(corpus)
}

/// `c06StreamedCorpusArtifact` — the corpus artifact at or above the
/// multipart floor, required to exist (the fingerprint validation already
/// demands one; this names it).
fn streamed_corpus_artifact(corpus: &Corpus) -> Result<&SeededArtifact, String> {
    corpus
        .artifacts
        .iter()
        .find(|a| a.streamed)
        .ok_or_else(|| {
            format!("the perturbation table has no unchanged-length streamed-body row to act on: the base fingerprint records no body at or above the {STREAMED_BODY_FLOOR_BYTES}-byte multipart floor")
        })
}

/// `c06OrdinaryCorpusArtifact` — the first below-floor corpus artifact.
fn ordinary_corpus_artifact(corpus: &Corpus) -> Result<&SeededArtifact, String> {
    corpus
        .artifacts
        .iter()
        .find(|a| !a.streamed)
        .ok_or_else(|| {
            "the perturbation table has no ordinary body to act on: the fingerprint covers no below-floor artifact"
                .to_owned()
        })
}

/// `decode_hex_32` — a 64-hex-char sha-256 into its 32 bytes.
fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// The probe names and the reversible grant.
// ---------------------------------------------------------------------------

const EQUIVALENCE_PROBE_TABLE: &str = "c06_equivalence_probe";
const EQUIVALENCE_PROBE_INDEX: &str = "c06_equivalence_probe_idx";
const EQUIVALENCE_PROBE_FUNCTION: &str = "c06_equivalence_probe";
const EQUIVALENCE_GRANT_RELATION: &str = "central.approvals";
const EQUIVALENCE_GRANT_ROLE: &str = "central_runtime";
const EQUIVALENCE_GRANT_PRIVILEGE: &str = "SELECT";
/// `c06EquivalenceTruncation` — 101 bytes, not one: a one-byte truncation
/// is also a digest change a size comparison could be argued to have
/// caught by accident.
const EQUIVALENCE_TRUNCATION: i64 = 101;

fn create_probe_function(kit: &CorruptionKit, body: i64) -> Result<(), String> {
    kit.exec(
        "install the probe function",
        &format!("CREATE OR REPLACE FUNCTION central.{EQUIVALENCE_PROBE_FUNCTION}() RETURNS integer LANGUAGE sql IMMUTABLE AS $c06$ SELECT {body} $c06$"),
        &[],
    )
}

fn drop_probe_function(kit: &CorruptionKit) -> Result<(), String> {
    kit.exec(
        "remove the probe function",
        &format!("DROP FUNCTION central.{EQUIVALENCE_PROBE_FUNCTION}()"),
        &[],
    )
}

fn drop_probe_function_if_present(kit: &CorruptionKit) -> Result<(), String> {
    kit.exec(
        "remove the probe function",
        &format!("DROP FUNCTION IF EXISTS central.{EQUIVALENCE_PROBE_FUNCTION}()"),
        &[],
    )
}

/// `c06RequireTheGrantThisPerturbationRemoves` — refuse the privilege row
/// on an instance where the grant it removes is not there: without it the
/// row would REVOKE nothing and then report that the comparison is blind
/// to a privilege change it was never shown.
fn require_the_grant_this_perturbation_removes(kit: &CorruptionKit) -> Result<(), String> {
    let granted = kit.query_scalar_bool(
        "read whether the runtime role holds the grant",
        "SELECT has_table_privilege($1, $2, $3)",
        &[
            Bind::Text(EQUIVALENCE_GRANT_ROLE.to_owned()),
            Bind::Text(EQUIVALENCE_GRANT_RELATION.to_owned()),
            Bind::Text(EQUIVALENCE_GRANT_PRIVILEGE.to_owned()),
        ],
    )?;
    if !granted {
        return Err(format!(
            "{EQUIVALENCE_GRANT_ROLE} does not hold {EQUIVALENCE_GRANT_PRIVILEGE} on {EQUIVALENCE_GRANT_RELATION}, so the privilege perturbation would revoke nothing and would then report that the comparison is blind to a privilege change it was never shown"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The perturbation table.
// ---------------------------------------------------------------------------

type Undo<'a> = Box<dyn FnOnce() -> Result<(), String> + Send + 'a>;
type ApplyFn = for<'a> fn(&'a CorruptionKit, &'a Corpus) -> Result<Undo<'a>, String>;
type PrepareFn = for<'a> fn(&'a CorruptionKit) -> Result<Undo<'a>, String>;
type ExpectedFn = fn(&StateFingerprint, &Corpus) -> Vec<String>;

/// `c06StateEquivalencePerturbation` — one row: a single-axis change (or
/// the minimal set of axes the change must move, declared), an Apply that
/// returns its own undo, and the exact report the comparison must produce.
struct EquivalencePerturbation {
    name: &'static str,
    axes: &'static [EquivalenceAxis],
    prepare: Option<PrepareFn>,
    apply: ApplyFn,
    expected: ExpectedFn,
    same_length_streamed_body: bool,
}

fn row_count_in(base: &StateFingerprint, table: &str) -> i64 {
    base.tables
        .iter()
        .find(|t| t.name == table)
        .map(|t| t.row_count)
        .unwrap_or(0)
}

/// `c06StateEquivalencePerturbations` — the table itself, ported row for
/// row. The SQL runs through the kit's exec with binds; nothing is
/// interpolated that is not already a constant of this file.
fn state_equivalence_perturbations() -> Vec<EquivalencePerturbation> {
    vec![
        EquivalencePerturbation {
            name: "a task row's title was rewritten, leaving the row count alone",
            axes: &[EquivalenceAxis::TableContent],
            prepare: None,
            apply: |kit, corpus| {
                kit.exec(
                    "rewrite a task title",
                    "UPDATE central.tasks SET title = title || '-c06-equivalence-probe' WHERE id = $1::uuid",
                    &[Bind::Text(corpus.task_id.clone())],
                )?;
                let task = corpus.task_id.clone();
                Ok(Box::new(move || {
                    kit.exec(
                        "restore the task title",
                        "UPDATE central.tasks SET title = replace(title, '-c06-equivalence-probe', '') WHERE id = $1::uuid",
                        &[Bind::Text(task)],
                    )
                }))
            },
            expected: |_, _| vec!["table central.tasks has different contents".to_owned()],
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            name: "a workspace row was inserted",
            axes: &[
                EquivalenceAxis::TableRowCount,
                EquivalenceAxis::TableContent,
            ],
            prepare: None,
            apply: |kit, _| {
                let inserted: String = kit
                    .conn
                    .run(|c| {
                        Box::pin(async move {
                            sqlx::query_scalar(
                                "INSERT INTO central.workspaces (id, state, owner_principal_id)
                                 VALUES (gen_random_uuid(), 'active', 'c06-synthetic-equivalence-probe') RETURNING id::text",
                            )
                            .fetch_one(&mut *c)
                            .await
                            .map_err(|e| {
                                central_foundation::failure::Failure::internal(
                                    "c06",
                                    format!("insert the probe workspace: {e}"),
                                )
                            })
                        })
                    })
                    .map_err(|e| e.to_string())?;
                Ok(Box::new(move || {
                    kit.exec(
                        "remove the probe workspace",
                        "DELETE FROM central.workspaces WHERE id = $1::uuid",
                        &[Bind::Text(inserted)],
                    )
                }))
            },
            expected: |base, _| {
                vec![
                    format!(
                        "table central.workspaces holds {} rows, want {}",
                        row_count_in(base, "central.workspaces") + 1,
                        row_count_in(base, "central.workspaces")
                    ),
                    "table central.workspaces has different contents".to_owned(),
                ]
            },
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            name: "an index was created on the artifacts relation",
            axes: &[EquivalenceAxis::TableSchema],
            prepare: None,
            apply: |kit, _| {
                kit.exec(
                    "create the probe index",
                    &format!("CREATE INDEX {EQUIVALENCE_PROBE_INDEX} ON central.artifacts (state)"),
                    &[],
                )?;
                Ok(Box::new(move || {
                    kit.exec(
                        "drop the probe index",
                        &format!("DROP INDEX central.{EQUIVALENCE_PROBE_INDEX}"),
                        &[],
                    )
                }))
            },
            expected: |_, _| vec!["table central.artifacts has a different schema".to_owned()],
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            name: "the runtime role's SELECT grant was revoked from a relation",
            axes: &[EquivalenceAxis::TableSchema],
            prepare: None,
            apply: |kit, _| {
                require_the_grant_this_perturbation_removes(kit)?;
                kit.exec(
                    "revoke the runtime grant",
                    &format!("REVOKE {EQUIVALENCE_GRANT_PRIVILEGE} ON {EQUIVALENCE_GRANT_RELATION} FROM {EQUIVALENCE_GRANT_ROLE}"),
                    &[],
                )?;
                Ok(Box::new(move || {
                    kit.exec(
                        "restore the runtime grant",
                        &format!("GRANT {EQUIVALENCE_GRANT_PRIVILEGE} ON {EQUIVALENCE_GRANT_RELATION} TO {EQUIVALENCE_GRANT_ROLE}"),
                        &[],
                    )
                }))
            },
            expected: |_, _| {
                vec![format!(
                    "table {EQUIVALENCE_GRANT_RELATION} has a different schema"
                )]
            },
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            name: "a relation was added to the schema",
            axes: &[EquivalenceAxis::TablePresence],
            prepare: None,
            apply: |kit, _| {
                kit.exec(
                    "create the probe relation",
                    &format!(
                        "CREATE TABLE central.{EQUIVALENCE_PROBE_TABLE} (id integer NOT NULL)"
                    ),
                    &[],
                )?;
                Ok(Box::new(move || {
                    kit.exec(
                        "drop the probe relation",
                        &format!("DROP TABLE central.{EQUIVALENCE_PROBE_TABLE}"),
                        &[],
                    )
                }))
            },
            expected: |_, _| {
                vec![format!(
                    "table central.{EQUIVALENCE_PROBE_TABLE} is present after and was absent before"
                )]
            },
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            name: "a relation was removed from the schema",
            axes: &[EquivalenceAxis::TablePresence],
            prepare: Some(|kit| {
                kit.exec(
                    "create the probe relation this row removes",
                    &format!(
                        "CREATE TABLE central.{EQUIVALENCE_PROBE_TABLE} (id integer NOT NULL)"
                    ),
                    &[],
                )?;
                Ok(Box::new(move || {
                    kit.exec(
                        "drop the probe relation",
                        &format!("DROP TABLE IF EXISTS central.{EQUIVALENCE_PROBE_TABLE}"),
                        &[],
                    )
                }))
            }),
            apply: |kit, _| {
                kit.exec(
                    "drop the probe relation",
                    &format!("DROP TABLE central.{EQUIVALENCE_PROBE_TABLE}"),
                    &[],
                )?;
                Ok(Box::new(move || {
                    kit.exec(
                        "recreate the probe relation",
                        &format!(
                            "CREATE TABLE central.{EQUIVALENCE_PROBE_TABLE} (id integer NOT NULL)"
                        ),
                        &[],
                    )
                }))
            },
            expected: |_, _| {
                vec![format!(
                    "table central.{EQUIVALENCE_PROBE_TABLE} is absent after"
                )]
            },
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            // THE ROW SLICE C ACCEPTANCE CONDITION #9 IS ABOUT: a corrupted
            // streamed body of the SAME LENGTH is exactly the case a size
            // comparison misses, and the LAST byte is exactly the case a
            // reader that gives up early misses — on a multipart object
            // every part must have been read.
            name: "the streamed body was replaced with different bytes of the same length",
            axes: &[EquivalenceAxis::ArtifactBody],
            prepare: None,
            apply: |kit, corpus| {
                let streamed = streamed_corpus_artifact(corpus)?;
                let (original, size) = kit.spool_body_to_temp(&streamed.ready_key)?;
                let injured_path =
                    std::env::temp_dir().join(format!("c06-injured-body-{}", Uuid::now_v7()));
                // Copy the spooled original, flip the last byte, write it
                // back through the production staging path.
                let result = (|| -> Result<(), String> {
                    std::fs::copy(&original, &injured_path)
                        .map_err(|e| format!("spool the injured copy: {e}"))?;
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&injured_path)
                        .map_err(|e| format!("open the injured copy: {e}"))?;
                    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
                    let mut file = file;
                    file.seek(SeekFrom::Start((size - 1) as u64))
                        .map_err(|e| format!("seek the last byte: {e}"))?;
                    let mut last = [0u8; 1];
                    file.read_exact(&mut last)
                        .map_err(|e| format!("read the spooled last byte: {e}"))?;
                    last[0] ^= 0xFF;
                    file.seek(SeekFrom::Start((size - 1) as u64))
                        .map_err(|e| format!("seek the last byte: {e}"))?;
                    file.write_all(&last)
                        .map_err(|e| format!("flip the spooled last byte: {e}"))?;
                    drop(file);
                    kit.put_body_from_file(&streamed.ready_key, &injured_path, size)?;
                    Ok(())
                })();
                let _ = std::fs::remove_file(&injured_path);
                result?;
                let key = streamed.ready_key.clone();
                Ok(Box::new(move || {
                    let undo = kit.put_body_from_file(&key, &original, size);
                    let _ = std::fs::remove_file(&original);
                    undo
                }))
            },
            expected: |_, corpus| {
                let streamed = match streamed_corpus_artifact(corpus) {
                    Ok(s) => s.id.clone(),
                    Err(_) => "the-streamed-artifact".to_owned(),
                };
                vec![format!("artifact {streamed} has a different body")]
            },
            same_length_streamed_body: true,
        },
        EquivalencePerturbation {
            name: "an ordinary body was truncated and the recorded size followed it",
            axes: &[
                EquivalenceAxis::ArtifactSize,
                EquivalenceAxis::ArtifactBody,
                EquivalenceAxis::ArtifactMetadata,
                EquivalenceAxis::TableContent,
            ],
            prepare: None,
            apply: |kit, corpus| {
                let ordinary = ordinary_corpus_artifact(corpus)?;
                let original = kit.read_body(&ordinary.ready_key)?;
                kit.put_body(
                    &ordinary.ready_key,
                    original[..original.len() - EQUIVALENCE_TRUNCATION as usize].to_vec(),
                )?;
                kit.exec(
                    "follow the truncation in the recorded size",
                    "UPDATE central.artifacts SET size = size - $2 WHERE id = $1::uuid",
                    &[
                        Bind::Text(ordinary.id.clone()),
                        Bind::I64(EQUIVALENCE_TRUNCATION),
                    ],
                )?;
                let key = ordinary.ready_key.clone();
                let id = ordinary.id.clone();
                Ok(Box::new(move || {
                    kit.put_body(&key, original)?;
                    kit.exec(
                        "restore the recorded size",
                        "UPDATE central.artifacts SET size = size + $2 WHERE id = $1::uuid",
                        &[Bind::Text(id), Bind::I64(EQUIVALENCE_TRUNCATION)],
                    )
                }))
            },
            expected: |_, corpus| {
                let ordinary = match ordinary_corpus_artifact(corpus) {
                    Ok(o) => o,
                    Err(_) => return vec![],
                };
                vec![
                    format!(
                        "artifact {} holds {} bytes, want {}",
                        ordinary.id,
                        ordinary.size - EQUIVALENCE_TRUNCATION,
                        ordinary.size
                    ),
                    format!("artifact {} has a different body", ordinary.id),
                    format!("artifact {} has different metadata", ordinary.id),
                    "table central.artifacts has different contents".to_owned(),
                ]
            },
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            // The other half of condition #9's subject: the flag is derived
            // from the size, so this row declares every axis the cut moves.
            name: "the streamed body was cut below the multipart floor, so it is no longer streamed",
            axes: &[
                EquivalenceAxis::ArtifactStreamed,
                EquivalenceAxis::ArtifactSize,
                EquivalenceAxis::ArtifactBody,
                EquivalenceAxis::ArtifactMetadata,
                EquivalenceAxis::TableContent,
            ],
            prepare: None,
            apply: |kit, corpus| {
                let streamed = streamed_corpus_artifact(corpus)?;
                let (original, size) = kit.spool_body_to_temp(&streamed.ready_key)?;
                let cut = size - (STREAMED_BODY_FLOOR_BYTES - 1);
                if cut <= 0 {
                    let _ = std::fs::remove_file(&original);
                    return Err(format!(
                        "the streamed body is {size} bytes and the multipart floor is {STREAMED_BODY_FLOOR_BYTES}; it cannot be cut below the floor"
                    ));
                }
                let below = STREAMED_BODY_FLOOR_BYTES - 1;
                let prefix = {
                    use std::io::Read as _;
                    let mut source = std::fs::File::open(&original)
                        .map_err(|e| format!("open the spooled original: {e}"))?;
                    let mut prefix = vec![0u8; below as usize];
                    source
                        .read_exact(&mut prefix)
                        .map_err(|e| format!("read the below-floor prefix: {e}"))?;
                    prefix
                };
                kit.put_body(&streamed.ready_key, prefix)?;
                kit.exec(
                    "follow the cut in the recorded size",
                    "UPDATE central.artifacts SET size = $2 WHERE id = $1::uuid",
                    &[Bind::Text(streamed.id.clone()), Bind::I64(below)],
                )?;
                let key = streamed.ready_key.clone();
                let id = streamed.id.clone();
                Ok(Box::new(move || {
                    kit.put_body_from_file(&key, &original, size)?;
                    let restore = kit.exec(
                        "restore the recorded size",
                        "UPDATE central.artifacts SET size = $2 WHERE id = $1::uuid",
                        &[Bind::Text(id), Bind::I64(size)],
                    );
                    let _ = std::fs::remove_file(&original);
                    restore
                }))
            },
            expected: |_, corpus| {
                let streamed = match streamed_corpus_artifact(corpus) {
                    Ok(s) => s,
                    Err(_) => return vec![],
                };
                vec![
                    format!(
                        "artifact {} holds {} bytes, want {}",
                        streamed.id,
                        STREAMED_BODY_FLOOR_BYTES - 1,
                        streamed.size
                    ),
                    format!("artifact {} has a different body", streamed.id),
                    format!("artifact {} changed streamed flag, now false", streamed.id),
                    format!("artifact {} has different metadata", streamed.id),
                    "table central.artifacts has different contents".to_owned(),
                ]
            },
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            name: "an artifact row's media type was altered, leaving its body alone",
            axes: &[
                EquivalenceAxis::ArtifactMetadata,
                EquivalenceAxis::TableContent,
            ],
            prepare: None,
            apply: |kit, corpus| {
                let ordinary = ordinary_corpus_artifact(corpus)?;
                kit.exec(
                    "alter the recorded media type",
                    "UPDATE central.artifacts SET media_type = 'application/c06-equivalence-probe' WHERE id = $1::uuid",
                    &[Bind::Text(ordinary.id.clone())],
                )?;
                let id = ordinary.id.clone();
                Ok(Box::new(move || {
                    kit.exec(
                        "restore the recorded media type",
                        "UPDATE central.artifacts SET media_type = 'application/octet-stream' WHERE id = $1::uuid",
                        &[Bind::Text(id)],
                    )
                }))
            },
            expected: |_, corpus| {
                let ordinary = match ordinary_corpus_artifact(corpus) {
                    Ok(o) => o,
                    Err(_) => return vec![],
                };
                vec![
                    format!("artifact {} has different metadata", ordinary.id),
                    "table central.artifacts has different contents".to_owned(),
                ]
            },
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            name: "an artifact was given a delete intent, so it leaves the set the backup carries",
            axes: &[
                EquivalenceAxis::ArtifactPresence,
                EquivalenceAxis::TableContent,
            ],
            prepare: None,
            apply: |kit, corpus| {
                let ordinary = ordinary_corpus_artifact(corpus)?;
                kit.exec(
                    "record a delete intent",
                    "UPDATE central.artifacts SET delete_intent_at = now() WHERE id = $1::uuid",
                    &[Bind::Text(ordinary.id.clone())],
                )?;
                let id = ordinary.id.clone();
                Ok(Box::new(move || {
                    kit.exec(
                        "withdraw the delete intent",
                        "UPDATE central.artifacts SET delete_intent_at = NULL WHERE id = $1::uuid",
                        &[Bind::Text(id)],
                    )
                }))
            },
            expected: |_, corpus| {
                let ordinary = match ordinary_corpus_artifact(corpus) {
                    Ok(o) => o,
                    Err(_) => return vec![],
                };
                vec![
                    format!("artifact {} is absent after", ordinary.id),
                    "table central.artifacts has different contents".to_owned(),
                ]
            },
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            name: "a function was added to the schema",
            axes: &[EquivalenceAxis::SchemaObjectPresence],
            prepare: None,
            apply: |kit, _| {
                create_probe_function(kit, 1)?;
                Ok(Box::new(move || drop_probe_function(kit)))
            },
            expected: |_, _| {
                vec![format!(
                    "schema object {EQUIVALENCE_PROBE_FUNCTION}() of kind function is present after"
                )]
            },
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            name: "a function was removed from the schema",
            axes: &[EquivalenceAxis::SchemaObjectPresence],
            prepare: Some(|kit| {
                create_probe_function(kit, 1)?;
                Ok(Box::new(move || drop_probe_function_if_present(kit)))
            }),
            apply: |kit, _| {
                drop_probe_function(kit)?;
                Ok(Box::new(move || create_probe_function(kit, 1)))
            },
            expected: |_, _| {
                vec![format!(
                    "schema object {EQUIVALENCE_PROBE_FUNCTION}() of kind function is absent after"
                )]
            },
            same_length_streamed_body: false,
        },
        EquivalencePerturbation {
            // THE BODY, and it is the row that needs Prepare: a function
            // body cannot be perturbed on an instance that holds no such
            // function, so the row installs one, captures its base with it
            // in place, and replaces ONLY its body.
            name: "a function's body was replaced, leaving its signature, volatility, owner and privileges alone",
            axes: &[EquivalenceAxis::SchemaObjectDefn],
            prepare: Some(|kit| {
                create_probe_function(kit, 1)?;
                Ok(Box::new(move || drop_probe_function_if_present(kit)))
            }),
            apply: |kit, _| {
                create_probe_function(kit, 2)?;
                Ok(Box::new(move || create_probe_function(kit, 1)))
            },
            expected: |_, _| {
                vec![format!(
                    "schema object {EQUIVALENCE_PROBE_FUNCTION}() of kind function has a different definition"
                )]
            },
            same_length_streamed_body: false,
        },
    ]
}

// ---------------------------------------------------------------------------
// The axis attribution machinery.
// ---------------------------------------------------------------------------

/// `c06ForEachCommon*` — apply `f(from, into)` for every element present
/// in BOTH collections, keyed the way the comparison pairs them.
fn for_each_common_table(
    base: &[fingerprint::TableFingerprint],
    into: &mut [fingerprint::TableFingerprint],
    apply: impl Fn(&fingerprint::TableFingerprint, &mut fingerprint::TableFingerprint),
) {
    let by_name: HashMap<&str, &fingerprint::TableFingerprint> =
        base.iter().map(|t| (t.name.as_str(), t)).collect();
    for target in into.iter_mut() {
        if let Some(from) = by_name.get(target.name.as_str()) {
            apply(from, target);
        }
    }
}

fn for_each_common_artifact(
    base: &[ArtifactFingerprint],
    into: &mut [ArtifactFingerprint],
    apply: impl Fn(&ArtifactFingerprint, &mut ArtifactFingerprint),
) {
    let by_id: HashMap<&str, &ArtifactFingerprint> =
        base.iter().map(|a| (a.id.as_str(), a)).collect();
    for target in into.iter_mut() {
        if let Some(from) = by_id.get(target.id.as_str()) {
            apply(from, target);
        }
    }
}

fn schema_object_key_of(object: &fingerprint::SchemaObjectFingerprint) -> String {
    format!("{}\t{}", object.kind, object.name)
}

fn for_each_common_schema_object(
    base: &[fingerprint::SchemaObjectFingerprint],
    into: &mut [fingerprint::SchemaObjectFingerprint],
    apply: impl Fn(&fingerprint::SchemaObjectFingerprint, &mut fingerprint::SchemaObjectFingerprint),
) {
    let by_key: HashMap<String, &fingerprint::SchemaObjectFingerprint> =
        base.iter().map(|o| (schema_object_key_of(o), o)).collect();
    for target in into.iter_mut() {
        if let Some(from) = by_key.get(&schema_object_key_of(target)) {
            apply(from, target);
        }
    }
}

fn restore_table_presence(
    base: &[fingerprint::TableFingerprint],
    perturbed: &[fingerprint::TableFingerprint],
) -> Vec<fingerprint::TableFingerprint> {
    let in_base: HashMap<&str, &fingerprint::TableFingerprint> =
        base.iter().map(|t| (t.name.as_str(), t)).collect();
    let mut kept = Vec::new();
    let mut present = HashSet::new();
    for table in perturbed {
        if in_base.contains_key(table.name.as_str()) {
            present.insert(table.name.clone());
            kept.push(table.clone());
        }
    }
    for table in base {
        if !present.contains(&table.name) {
            kept.push(table.clone());
        }
    }
    kept
}

fn restore_artifact_presence(
    base: &[ArtifactFingerprint],
    perturbed: &[ArtifactFingerprint],
) -> Vec<ArtifactFingerprint> {
    let in_base: HashMap<&str, &ArtifactFingerprint> =
        base.iter().map(|a| (a.id.as_str(), a)).collect();
    let mut kept = Vec::new();
    let mut present = HashSet::new();
    for artifact in perturbed {
        if in_base.contains_key(artifact.id.as_str()) {
            present.insert(artifact.id.clone());
            kept.push(artifact.clone());
        }
    }
    for artifact in base {
        if !present.contains(&artifact.id) {
            kept.push(artifact.clone());
        }
    }
    kept
}

fn restore_schema_object_presence(
    base: &[fingerprint::SchemaObjectFingerprint],
    perturbed: &[fingerprint::SchemaObjectFingerprint],
) -> Vec<fingerprint::SchemaObjectFingerprint> {
    let in_base: HashMap<String, &fingerprint::SchemaObjectFingerprint> =
        base.iter().map(|o| (schema_object_key_of(o), o)).collect();
    let mut kept = Vec::new();
    let mut present = HashSet::new();
    for object in perturbed {
        let key = schema_object_key_of(object);
        if in_base.contains_key(&key) {
            present.insert(key);
            kept.push(object.clone());
        }
    }
    for object in base {
        if !present.contains(&schema_object_key_of(object)) {
            kept.push(object.clone());
        }
    }
    kept
}

/// `c06NeutralizeAxis` — the perturbed fingerprint with one axis's
/// contribution replaced by the base's. `Err(())` when the axis is not
/// known, so a field added to the structs and not to this match fails the
/// attribution loudly rather than being counted as an axis no row moves.
fn neutralize_axis(
    base: &StateFingerprint,
    perturbed: &StateFingerprint,
    axis: EquivalenceAxis,
) -> Result<StateFingerprint, ()> {
    let mut neutral = StateFingerprint {
        tables: perturbed.tables.clone(),
        artifacts: perturbed.artifacts.clone(),
        schema_objects: perturbed.schema_objects.clone(),
    };
    match axis {
        EquivalenceAxis::TablePresence => {
            neutral.tables = restore_table_presence(&base.tables, &neutral.tables);
        }
        EquivalenceAxis::TableRowCount => {
            for_each_common_table(&base.tables, &mut neutral.tables, |from, into| {
                into.row_count = from.row_count;
            });
        }
        EquivalenceAxis::TableContent => {
            for_each_common_table(&base.tables, &mut neutral.tables, |from, into| {
                into.content_sha256 = from.content_sha256.clone();
            });
        }
        EquivalenceAxis::TableSchema => {
            for_each_common_table(&base.tables, &mut neutral.tables, |from, into| {
                into.schema_sha256 = from.schema_sha256.clone();
            });
        }
        EquivalenceAxis::ArtifactPresence => {
            neutral.artifacts = restore_artifact_presence(&base.artifacts, &neutral.artifacts);
        }
        EquivalenceAxis::ArtifactSize => {
            for_each_common_artifact(&base.artifacts, &mut neutral.artifacts, |from, into| {
                into.size_bytes = from.size_bytes;
            });
        }
        EquivalenceAxis::ArtifactBody => {
            for_each_common_artifact(&base.artifacts, &mut neutral.artifacts, |from, into| {
                into.body_sha256 = from.body_sha256.clone();
            });
        }
        EquivalenceAxis::ArtifactStreamed => {
            for_each_common_artifact(&base.artifacts, &mut neutral.artifacts, |from, into| {
                into.streamed = from.streamed;
            });
        }
        EquivalenceAxis::ArtifactMetadata => {
            for_each_common_artifact(&base.artifacts, &mut neutral.artifacts, |from, into| {
                into.metadata_sha256 = from.metadata_sha256.clone();
            });
        }
        EquivalenceAxis::SchemaObjectPresence => {
            neutral.schema_objects =
                restore_schema_object_presence(&base.schema_objects, &neutral.schema_objects);
        }
        EquivalenceAxis::SchemaObjectDefn => {
            for_each_common_schema_object(
                &base.schema_objects,
                &mut neutral.schema_objects,
                |from, into| {
                    into.definition_sha256 = from.definition_sha256.clone();
                },
            );
        }
    }
    Ok(neutral)
}

/// `c06AxesTheComparisonAttributes` — which axes the real comparison's
/// reports between two fingerprints are attributable to, made BY the
/// comparison: for each axis, its contribution is neutralised in the
/// perturbed fingerprint and divergences is asked again. The two
/// anti-vacuity rules hold on every call: neutralising may never ADD a
/// report, and neutralising EVERY axis must leave the comparison empty.
pub(crate) fn axes_the_comparison_attributes(
    base: &StateFingerprint,
    perturbed: &StateFingerprint,
) -> Result<Vec<EquivalenceAxis>, String> {
    let axes = sorted_axes(&axes_the_comparison_can_report());
    let full = fingerprint::divergences(base, perturbed);
    if full.count == 0 {
        return Err(
            "the axis attribution was asked to decompose a comparison that reported nothing"
                .to_owned(),
        );
    }
    let mut attributed = Vec::new();
    for axis in &axes {
        let Ok(neutral) = neutralize_axis(base, perturbed, *axis) else {
            return Err(format!(
                "{} is an axis the comparison can report and neutralize_axis does not know how to neutralise it; every row's attribution would silently treat that axis as unmoved",
                axis.as_str()
            ));
        };
        let reduced = fingerprint::divergences(base, &neutral);
        if reduced.count > full.count {
            return Err(format!(
                "neutralising {} raised the comparison from {} reports to {}; the neutralisation is editing something other than that axis",
                axis.as_str(),
                full.count,
                reduced.count
            ));
        } else if reduced.count < full.count {
            attributed.push(*axis);
        }
    }
    let mut neutral = perturbed.clone();
    for axis in &axes {
        let Ok(next) = neutralize_axis(base, &neutral, *axis) else {
            return Err(format!("{} cannot be neutralised", axis.as_str()));
        };
        neutral = next;
    }
    let residue = fingerprint::divergences(base, &neutral);
    if !residue.empty() {
        return Err(format!(
            "neutralising every one of the {} axes still leaves the comparison reporting {residue}; part of this change is not attributable to any axis",
            axes.len()
        ));
    }
    if attributed.is_empty() {
        return Err(format!(
            "the comparison reported {full} and neutralising each axis in turn removed none of it, while neutralising all of them removed all of it; no single axis is attributable and the row cannot be held to a declaration"
        ));
    }
    Ok(attributed)
}

// ---------------------------------------------------------------------------
// The discrimination battery.
// ---------------------------------------------------------------------------

/// `c06RequireTheExpectationNamesItsSubject` — the second whitespace field
/// of every report names the object that moved (`table X`, `artifact X`,
/// `schema object NAME of kind K`); an expectation that does not contain
/// it names no particular object.
fn require_the_expectation_names_its_subject(
    row: usize,
    name: &str,
    want: &str,
    reported: &str,
) -> Result<(), String> {
    let fields: Vec<&str> = reported.split_whitespace().collect();
    let subject = if reported.starts_with("schema object ") {
        fields.get(2).copied().unwrap_or("")
    } else {
        fields.get(1).copied().unwrap_or("")
    };
    if subject.is_empty() {
        return Err(format!(
            "perturbation {row} ({name}) matched the report {reported:?}, which carries no subject at all; every divergence the comparison produces names its kind and then the object"
        ));
    }
    if want.contains(subject) {
        return Ok(());
    }
    Err(format!(
        "perturbation {row} ({name}) expects {want:?}, which does not name {subject} -- the object the report it matched is about ({reported:?}). An expectation that names no subject is satisfied by the comparison reporting the same kind of change about a different table, artifact or schema object"
    ))
}

/// `c06RequireExactlyTheseDivergences` — the declared report set, in both
/// directions: a report the row did not declare is a change it did not
/// intend; a declared report the comparison did not produce is the
/// blindness this battery exists to catch.
fn require_exactly_these_divergences(
    row: usize,
    perturbation: &EquivalencePerturbation,
    base: &StateFingerprint,
    corpus: &Corpus,
    divergence: &fingerprint::FingerprintDivergence,
) -> Result<(), String> {
    let expected = (perturbation.expected)(base, corpus);
    if expected.is_empty() {
        return Err(format!(
            "perturbation {row} ({}) declares no expected divergence at all, so it asserts that a change to the instance produces nothing",
            perturbation.name
        ));
    }
    if divergence.count != expected.len() {
        return Err(format!(
            "perturbation {row} ({}) declares {} divergences and the comparison found {}: {divergence}",
            perturbation.name,
            expected.len(),
            divergence.count
        ));
    }
    let mut unmatched: Vec<String> = divergence.reported.clone();
    for want in &expected {
        let mut matches = 0usize;
        let mut matched_at = usize::MAX;
        for (index, reported) in unmatched.iter().enumerate() {
            if !reported.is_empty() && reported.contains(want) {
                matches += 1;
                matched_at = index;
            }
        }
        match matches {
            1 => {
                require_the_expectation_names_its_subject(
                    row,
                    perturbation.name,
                    want,
                    &unmatched[matched_at],
                )?;
                unmatched[matched_at] = String::new();
            }
            0 => {
                return Err(format!(
                    "perturbation {row} ({}) changed the instance and the comparison did NOT report {want:?}. A restore that lost exactly this would have compared equal to the pre-corruption fingerprint. What it did report: {divergence}",
                    perturbation.name
                ));
            }
            _ => {
                return Err(format!(
                    "perturbation {row} ({}) expects {want:?} and {matches} reported divergences match it, so this row's assertion cannot say which one it is about: {divergence}",
                    perturbation.name
                ));
            }
        }
    }
    for leftover in &unmatched {
        if !leftover.is_empty() {
            return Err(format!(
                "perturbation {row} ({}) produced a divergence it does not declare: {leftover:?}. Either the row is not the single-axis change it says it is, or an earlier row left residue",
                perturbation.name
            ));
        }
    }
    Ok(())
}

/// `c06RequireTheDeclaredAxesAreTheOnesTheComparisonAttributes` — grounds
/// a row's Axes declaration in what the row DID, using the comparison's
/// own attribution rather than a second reading of its output.
fn require_the_declared_axes_are_the_ones_the_comparison_attributes(
    row: usize,
    perturbation: &EquivalencePerturbation,
    base: &StateFingerprint,
    perturbed: &StateFingerprint,
) -> Result<(), String> {
    let attributed = axes_the_comparison_attributes(base, perturbed)?;
    let mut declared = BTreeSet::new();
    for axis in perturbation.axes {
        if !declared.insert(*axis) {
            return Err(format!(
                "perturbation {row} ({}) declares {} twice",
                perturbation.name,
                axis.as_str()
            ));
        }
    }
    let moved: BTreeSet<EquivalenceAxis> = attributed.iter().copied().collect();
    for axis in sorted_axes(&declared) {
        if !moved.contains(&axis) {
            return Err(format!(
                "perturbation {row} ({}) DECLARES {} and the comparison attributes nothing on that axis to it (it attributes {:?}). The declaration is what the completeness guard counts, so a row declaring an axis it does not move can make that guard green over an axis no row exercises",
                perturbation.name,
                axis.as_str(),
                attributed.iter().map(|a| a.as_str()).collect::<Vec<_>>()
            ));
        }
    }
    for axis in sorted_axes(&moved) {
        if !declared.contains(&axis) {
            return Err(format!(
                "perturbation {row} ({}) moves {} and does not declare it (it declares {:?}). Either the row is not the single-axis change it says it is, or the completeness guard is being told this row covers less than it does",
                perturbation.name,
                axis.as_str(),
                perturbation
                    .axes
                    .iter()
                    .map(|a| a.as_str())
                    .collect::<Vec<_>>()
            ));
        }
    }
    Ok(())
}

/// `c06RequireTheSameLengthClaimIsWhatTheRowDid` — the marked row must
/// have acted on a body the base fingerprint records as STREAMED, still
/// streamed, at the SAME recorded size, with a DIFFERENT body digest.
fn require_the_same_length_claim_is_what_the_row_did(
    row: usize,
    perturbation: &EquivalencePerturbation,
    base: &StateFingerprint,
    perturbed: &StateFingerprint,
) -> Result<(), String> {
    if !perturbation.same_length_streamed_body {
        return Ok(());
    }
    let by_id: HashMap<&str, &ArtifactFingerprint> = perturbed
        .artifacts
        .iter()
        .map(|a| (a.id.as_str(), a))
        .collect();
    for before in &base.artifacts {
        let Some(after) = by_id.get(before.id.as_str()) else {
            continue;
        };
        if *before == **after {
            continue;
        }
        if !before.streamed {
            return Err(format!(
                "perturbation {row} ({}) claims to replace a STREAMED body with different bytes of the same length, and the artifact it moved ({}) is not streamed in this row's base; the claim Slice C acceptance condition #9 rests on would be made by a row acting on an ordinary body",
                perturbation.name, before.id
            ));
        }
        if after.size_bytes != before.size_bytes {
            return Err(format!(
                "perturbation {row} ({}) claims the same length and moved artifact {} from {} bytes to {}; a size comparison alone would have caught this",
                perturbation.name, before.id, before.size_bytes, after.size_bytes
            ));
        }
        if !after.streamed {
            return Err(format!(
                "perturbation {row} ({}) claims to leave artifact {} streamed and it is not streamed after",
                perturbation.name, before.id
            ));
        }
        if after.body_sha256 == before.body_sha256 {
            return Err(format!(
                "perturbation {row} ({}) claims to replace the bytes of artifact {} and its body digest is unchanged",
                perturbation.name, before.id
            ));
        }
        return Ok(());
    }
    Err(format!(
        "perturbation {row} ({}) carries the same-length streamed-body claim and no artifact present in both fingerprints changed at all, so the row asserts condition #9's case over a change it did not make",
        perturbation.name
    ))
}

/// `c06RunOneStateEquivalencePerturbation` — one row, existing as its own
/// function for one reason: SO THE UNDO IS UNCONDITIONAL. Every undo is
/// returned by the call that made the change and is run in a Drop guard,
/// so a failure (Result or panic) still leaves the instance as the row
/// found it. The comparisons after an undo are skipped once the row has
/// already failed — they would replace the real failure with a second one
/// about residue — but the undo itself is never skipped.
#[allow(clippy::too_many_arguments)]
fn run_one_state_equivalence_perturbation(
    kit: &CorruptionKit,
    objects: &central_adapter_linux::backup::S3BackupObjectSource,
    base: &StateFingerprint,
    corpus: &Corpus,
    narrator: &mut dyn Narrator,
    row: usize,
    perturbation: &EquivalencePerturbation,
) -> Result<(), String> {
    // SO THE UNDO IS UNCONDITIONAL: each change hands back its undo and the
    // undo is dropped into a guard whose Drop runs it whether the row
    // passed, failed a check, or unwound. The comparisons after an undo are
    // skipped once the row has already failed — they would replace the
    // row's real failure with a second one about residue — but the undo
    // itself is never skipped.
    struct UndoOnDrop<'a>(Option<Undo<'a>>);
    impl Drop for UndoOnDrop<'_> {
        fn drop(&mut self) {
            if let Some(undo) = self.0.take() {
                let _ = undo();
            }
        }
    }

    let mut row_base = base.clone();
    let mut prepare_guard = UndoOnDrop(None);
    if let Some(prepare) = perturbation.prepare {
        prepare_guard.0 = Some(prepare(kit)?);
        // The row's own base, captured with its subject in place —
        // required to differ, or a Prepare that silently did nothing would
        // make this row a comparison against the battery base under
        // another name.
        let captured = scenario2::capture_state_fingerprint(&kit.conn, objects)?;
        if captured.equal(base) {
            return Err(format!(
                "perturbation {row} ({}) prepared its subject and the instance still compares equal to the battery's base; the preparation changed nothing, so this row's base is not the state it claims to be",
                perturbation.name
            ));
        }
        row_base = captured;
    }

    narrator.expect(&format!(
        "perturbation {row}, {}, is reported by the comparison as exactly {:?} and as nothing else",
        perturbation.name,
        (perturbation.expected)(&row_base, corpus)
    ));
    let undo_apply = (perturbation.apply)(kit, corpus)?;
    let mut apply_guard = UndoOnDrop(Some(undo_apply));

    let perturbed = scenario2::capture_state_fingerprint(&kit.conn, objects)?;
    let divergence = fingerprint::divergences(&row_base, &perturbed);
    // The same-length claim first, deliberately: a row that made the wrong
    // change would also fail the exact-set check, but it would fail citing
    // a divergence set rather than the claim that is wrong.
    require_the_same_length_claim_is_what_the_row_did(row, perturbation, &row_base, &perturbed)?;
    require_exactly_these_divergences(row, perturbation, &row_base, corpus, &divergence)?;
    require_the_declared_axes_are_the_ones_the_comparison_attributes(
        row,
        perturbation,
        &row_base,
        &perturbed,
    )?;
    narrator.record(format!(
        "perturbation {row} ({}) moved axes {:?} and the comparison reported exactly: {divergence}",
        perturbation.name,
        perturbation
            .axes
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>()
    ));

    // Success path only: run the apply undo explicitly so its result and
    // the reverted-equality check are asserted. On every failure above the
    // guard has already run it.
    if let Some(undo) = apply_guard.0.take() {
        undo().map_err(|e| {
            format!(
                "perturbation {row} ({}) could not be reverted: {e}",
                perturbation.name
            )
        })?;
    }
    let residue = fingerprint::divergences(
        &row_base,
        &scenario2::capture_state_fingerprint(&kit.conn, objects)?,
    );
    if !residue.empty() {
        return Err(format!(
            "perturbation {row} ({}) was reverted and the instance still differs from this row's base ({residue}); the row left residue, and every row after it would report divergences it did not cause",
            perturbation.name
        ));
    }
    if let Some(undo) = prepare_guard.0.take() {
        undo().map_err(|e| {
            format!(
                "perturbation {row} ({}) could not undo its preparation: {e}",
                perturbation.name
            )
        })?;
        let restored = fingerprint::divergences(
            base,
            &scenario2::capture_state_fingerprint(&kit.conn, objects)?,
        );
        if !restored.empty() {
            return Err(format!(
                "perturbation {row} ({}) undid its preparation and the instance still differs from the battery's base ({restored})",
                perturbation.name
            ));
        }
    }
    Ok(())
}

/// `c06RunStateEquivalenceDiscriminationBattery` — the proof that the
/// comparison scenario 7 makes is a comparison. It is given the base the
/// scenario itself compares against, so what is shown to discriminate is
/// literally the call whose empty answer the scenario reports as state
/// equivalence. The control comes first and is not optional.
fn run_state_equivalence_discrimination_battery(
    kit: &CorruptionKit,
    objects: &central_adapter_linux::backup::S3BackupObjectSource,
    base: &StateFingerprint,
    corpus: &Corpus,
    narrator: &mut dyn Narrator,
) -> Result<(), String> {
    let perturbations = state_equivalence_perturbations();
    if perturbations.is_empty() {
        return Err(
            "the perturbation table is empty, so this battery would report that the comparison discriminates having shown it nothing"
                .to_owned(),
        );
    }

    narrator.expect(
        "the instance compares EQUAL to the base fingerprint before any perturbation, so every divergence reported below is the perturbation's own",
    );
    let control = fingerprint::divergences(
        base,
        &scenario2::capture_state_fingerprint(&kit.conn, objects)?,
    );
    if !control.empty() {
        return Err(format!(
            "the discrimination battery's control failed: the instance does not compare equal to its base before anything was perturbed ({control}). Every row below would report divergences that are not the perturbation's, so the battery stops here rather than producing attributions a reader could not trust"
        ));
    }
    narrator.record(format!(
        "discrimination battery control: the instance compares equal to the base fingerprint (digest {}) before any perturbation",
        base.digest()
    ));

    for (index, perturbation) in perturbations.iter().enumerate() {
        run_one_state_equivalence_perturbation(
            kit,
            objects,
            base,
            corpus,
            narrator,
            index + 1,
            perturbation,
        )?;
    }

    narrator.expect(
        "the instance compares EQUAL to the base fingerprint again after every perturbation has been reverted",
    );
    let last = fingerprint::divergences(
        base,
        &scenario2::capture_state_fingerprint(&kit.conn, objects)?,
    );
    if !last.empty() {
        return Err(format!(
            "the instance does not compare equal to the base after the whole battery reverted ({last}); something this battery did was not undone, and the instance the run continues on is not the one it started with"
        ));
    }
    narrator.record(format!(
        "discrimination battery: {} single-axis perturbations, each reported by name against the base fingerprint and each reverted; the instance compares equal to the base at the end",
        perturbations.len()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// The restore-audit table set (SC-DEF-83).
// ---------------------------------------------------------------------------

/// `c06RestoreAuditTables` — the relations the restore act itself writes.
/// Pinned to exactly these three by the portable test below: a fourth name
/// here would be the exclusion list `divergences_except_content_of`
/// refuses to become.
pub(crate) fn restore_audit_tables() -> [&'static str; 3] {
    [
        "central.recovery_operations",
        "central.recovery_quarantines",
        "central.recovery_bootstrap_registrations",
    ]
}

/// `c06WithoutRestoreAuditTables`.
pub(crate) fn without_restore_audit_tables(names: &[String]) -> Vec<String> {
    let audit: HashSet<&str> = restore_audit_tables().into_iter().collect();
    names
        .iter()
        .filter(|n| !audit.contains(n.as_str()))
        .cloned()
        .collect()
}

/// `c06WithRestoreAuditTables` — union preserving order, no duplicates.
pub(crate) fn with_restore_audit_tables(names: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for name in names {
        if seen.insert(name.clone()) {
            out.push(name.clone());
        }
    }
    for audit in restore_audit_tables() {
        if seen.insert(audit.to_owned()) {
            out.push(audit.to_owned());
        }
    }
    out
}

/// `c06NameSetDifference` — how two name sets differ, both directions
/// named separately because they mean opposite things at step 3.
fn name_set_difference(left: &[String], right: &[String]) -> String {
    let in_left: HashSet<&str> = left.iter().map(|s| s.as_str()).collect();
    let in_right: HashSet<&str> = right.iter().map(|s| s.as_str()).collect();
    let mut only_left: Vec<&str> = in_left.difference(&in_right).copied().collect();
    let mut only_right: Vec<&str> = in_right.difference(&in_left).copied().collect();
    if only_left.is_empty() && only_right.is_empty() {
        return String::new();
    }
    only_left.sort();
    only_right.sort();
    format!(
        "{} differ that were not measured ({only_left:?}), {} were measured that no longer differ ({only_right:?})",
        only_left.len(),
        only_right.len()
    )
}

/// `c06RequireTheStreamedBodySurvived` — condition #9 by identity: every
/// streamed body the pre-corruption fingerprint records is present now,
/// still streamed, at its recorded length and digest.
fn require_the_streamed_body_survived(
    before: &StateFingerprint,
    after: &StateFingerprint,
) -> Result<(), String> {
    let recorded: Vec<&ArtifactFingerprint> =
        before.artifacts.iter().filter(|a| a.streamed).collect();
    if recorded.is_empty() {
        return Err(format!(
            "the pre-corruption fingerprint records no body at or above the {STREAMED_BODY_FLOOR_BYTES}-byte multipart floor, so Slice C acceptance condition #9 has no subject and every claim about streaming this scenario makes would be about nothing"
        ));
    }
    let present: HashMap<&str, &ArtifactFingerprint> =
        after.artifacts.iter().map(|a| (a.id.as_str(), a)).collect();
    for want in recorded {
        let Some(got) = present.get(want.id.as_str()) else {
            return Err(
                "the streamed body recorded before the corruption is not present now; condition #9's subject is gone"
                    .to_owned(),
            );
        };
        if !got.streamed {
            return Err(format!(
                "the body that was streamed before is now {} bytes, below the {STREAMED_BODY_FLOOR_BYTES}-byte multipart floor, so it is no longer the streamed subject condition #9 is about",
                got.size_bytes
            ));
        }
        if got.size_bytes != want.size_bytes {
            return Err(format!(
                "the streamed body is {} bytes and was {}",
                got.size_bytes, want.size_bytes
            ));
        }
        if got.body_sha256 != want.body_sha256 {
            return Err(
                "the streamed body is present at its original length and its bytes differ; a same-length corruption is exactly the case a size comparison misses, and condition #9 is about the bytes"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scenario 7.
// ---------------------------------------------------------------------------

struct ScenarioNarrator<'a> {
    id: &'a str,
    log: &'a mut ScenarioLog,
}

pub(crate) trait Narrator {
    fn expect(&mut self, what: &str);
    fn record(&mut self, what: String);
}

impl Narrator for ScenarioNarrator<'_> {
    fn expect(&mut self, what: &str) {
        expect78(self.id, what);
    }
    fn record(&mut self, what: String) {
        self.log.recordf(format_args!("{what}"));
    }
}

/// `c06Expect` for this file — the expectation with the CALLING scenario's
/// own scope disclosure attached, never scenario 2's: `s.Expect` is never
/// called bare, and a divergence reported under scenario 7's name carrying
/// scenario 2's scope statement would tell a reader the wrong contract.
fn expect78(id: &str, what: impl AsRef<str>) {
    let disclosure = if id.starts_with("c06.s8") {
        SCENARIO8_SCOPE_DISCLOSURE
    } else {
        SCENARIO7_SCOPE_DISCLOSURE
    };
    runner().attach_divergence(id, &format!("{}. {}", what.as_ref(), disclosure));
}

/// `c06PostRestoreStateEquivalence` — C06 scenario 7's body.
#[test]
fn c06_s7_state_equivalence() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    let id = "c06.s7.state_equivalence";
    slice_c::scenario(
        id,
        |profile| slice_c::unmet_precondition(id, profile).or_else(scenario2::missing_live_env),
        |_s| {
            let mut log = ScenarioLog::new(id);
            log.recordf(format_args!("{SCENARIO7_SCOPE_DISCLOSURE}"));
            crate::continuous_run::gate_the_sequence("c06.s6.authority_reset", &mut log)?;

            // --- 1. Both ends of the comparison exist. -------------------
            expect78(
                id,
                "the pre-corruption fingerprint the corruption scenario captured before injecting anything and the post-corruption fingerprint it recorded are both present, so the comparison has both ends",
            );
            let (before, corrupted, footprint) = {
                let records = crate::fixture::records();
                let Some(before) = records.pre_corruption.clone() else {
                    return Err("no pre-corruption fingerprint was recorded, so there is nothing to compare a restored instance against. c06.s2.corruption_detected captures it after its seed and before its first injection, and it cannot be re-derived later -- this scenario cannot substitute a fresh capture for it, because a fresh capture describes the state AFTER everything this run did".to_owned());
                };
                let Some(corrupted) = records.corrupted.clone() else {
                    return Err("no post-corruption fingerprint was recorded, so this scenario cannot show that the state it is about to call equivalent is not simply the state the corruption left. c06.s2.corruption_detected captures it".to_owned());
                };
                let footprint = records.authority_reset_footprint.clone();
                (before, corrupted, footprint)
            };

            // --- 2. The two ends differ. ----------------------------------
            expect78(
                id,
                "the pre-corruption and post-corruption fingerprints differ, so equality with the first is not automatically equality with the second",
            );
            let ends_differ = fingerprint::divergences(&before, &corrupted);
            if ends_differ.empty() {
                return Err("the pre-corruption and post-corruption fingerprints are the same state, so nothing scenario 2 injected changed anything the fingerprint covers; every comparison this scenario makes would hold whether or not a restore had happened".to_owned());
            }
            log.recordf(format_args!(
                "the two recorded fingerprints differ in {} places, so the comparison below is not vacuous",
                ends_differ.count
            ));

            // --- 3. The instance's state, captured through the same path. -
            let dsn = scenario2::require_env(crate::fixture::PG_DSN_ENV)
                .expect("the environment gate passed before this body ran");
            let s3 = scenario2::s3_config()?;
            let conn = Arc::new(connect_pg(&dsn)?);
            let runtime = Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .map_err(|e| format!("build the object-store runtime: {e}"))?,
            );
            let detection_store = Arc::new(
                central_adapter_s3::S3ObjectStore::new(s3.clone())
                    .map_err(|e| format!("compose the detection object store: {e}"))?,
            );
            let detection_objects = central_adapter_linux::backup::S3BackupObjectSource::new(
                detection_store.clone(),
                runtime.handle().clone(),
            )
            .map_err(|e| format!("compose the detection object reader: {e}"))?;

            expect78(
                id,
                "the instance's current state, captured through the same two stores scenario 1 captured it through, differs from the pre-corruption fingerprint in EXACTLY the tables scenario 6 measured the mandated C05 reset moving plus the three restore-audit relations the restore act itself writes, and in no other way at all",
            );
            let after = scenario2::capture_state_fingerprint(&conn, &detection_objects)?;
            log.recordf(format_args!(
                "post-restore capture: {} tables, {} rows, {} artifact bodies, {} streamed, {} schema objects, digest {}",
                after.tables.len(),
                after.total_rows(),
                after.artifacts.len(),
                after.streamed_bodies(),
                after.schema_objects.len(),
                after.digest()
            ));
            let Some(footprint) = footprint else {
                return Err("scenario 6 recorded no authority-reset footprint, so this scenario does not know which tables the mandated post-restore reset moved. It must not assume the answer is 'none': an unmeasured footprint exempts nothing and would fail this comparison for the reset rather than for the restore, which is the misdiagnosis this record exists to prevent. c06.s6.authority_reset measures it over its own body".to_owned());
            };
            let moved = fingerprint::content_divergent_tables(&before, &after);
            let compared_moved = without_restore_audit_tables(&moved);
            let compared_footprint = without_restore_audit_tables(&footprint);
            let difference = name_set_difference(&compared_moved, &compared_footprint);
            if !difference.is_empty() {
                return Err(format!(
                    "the tables whose rows differ from the pre-corruption fingerprint are not the tables scenario 6 measured the C05 reset moving: {difference}. A name on the left that scenario 6 did not measure is state this restore did not reproduce; a name on the right that no longer differs means scenario 6's before/after bracket did not span the reset it reports"
                ));
            }
            let content_exempt = with_restore_audit_tables(&footprint);
            let divergence =
                fingerprint::divergences_except_content_of(&before, &after, &content_exempt);
            if !divergence.empty() {
                return Err(format!(
                    "the instance diverges from the pre-corruption fingerprint outside the rows of the {} table(s) scenario 6 measured the reset moving plus the {} restore-audit relations: {divergence}",
                    footprint.len(),
                    restore_audit_tables().len()
                ));
            }
            log.recordf(format_args!(
                "the instance matches the pre-corruption fingerprint everywhere except the rows of the {} table(s) scenario 6 measured the mandated C05 reset moving ({footprint:?}) plus the {} restore-audit relations, and those are exactly the tables that differ",
                footprint.len(),
                restore_audit_tables().len()
            ));

            // --- 4. And it is not the corrupted state (a restatement). ----
            expect78(
                id,
                "the same capture DIFFERS from the post-corruption fingerprint, restating steps 2 and 3 at the place a reader looks for it",
            );
            let still_corrupted = fingerprint::divergences(&after, &corrupted);
            if still_corrupted.empty() {
                return Err("the instance matches the POST-corruption fingerprint as well as the pre-corruption one. Both cannot be true of two states that differ, so one of the two recorded fingerprints does not describe what it says it describes".to_owned());
            }
            log.recordf(format_args!(
                "the instance differs from the post-corruption fingerprint in {} places",
                still_corrupted.count
            ));

            // --- 5. The streamed body, named. -----------------------------
            expect78(
                id,
                format!(
                    "exactly one body at or above the {STREAMED_BODY_FLOOR_BYTES}-byte multipart floor is present, at its original length and its original digest read back through the real object store (Slice C acceptance condition #9)"
                ),
            );
            require_the_streamed_body_survived(&before, &after)?;
            log.recordf(format_args!(
                "streamed body present at its recorded length and digest; {} of {} fingerprinted bodies reach the {STREAMED_BODY_FLOOR_BYTES}-byte floor",
                after.streamed_bodies(),
                after.artifacts.len()
            ));

            // --- 6. And the comparison that just said "equal" discriminates.
            //
            // SC-DEF-87: the base is the step-3 post-restore capture, not the
            // pre-corruption fingerprint. The battery perturbs the instance
            // as it stands, so its base is the instance as it stands.
            let injection_store = Arc::new(
                central_adapter_s3::S3ObjectStore::new(s3.clone())
                    .map_err(|e| format!("compose the injection object store: {e}"))?,
            );
            let kit = CorruptionKit {
                conn: conn.clone(),
                store: injection_store.clone(),
                runtime: runtime.clone(),
            };
            let corpus = corpus_from_fingerprint(&conn, &kit, &after)?;
            let mut narrator = ScenarioNarrator { id, log: &mut log };
            run_state_equivalence_discrimination_battery(
                &kit,
                &detection_objects,
                &after,
                &corpus,
                &mut narrator,
            )
        },
    );
}

// ---------------------------------------------------------------------------
// Scenario 8 — the instruments, and what pins each of them.
// ---------------------------------------------------------------------------

/// `c06MinimumProfileProducers` — which catalogue entry must produce each
/// measurement, so an absent reading is reported as "the entry that takes
/// this reading did not take it" rather than "the bound was not met".
pub(crate) fn minimum_profile_producers() -> BTreeMap<MeasurementField, &'static str> {
    BTreeMap::from([
        (MeasurementField::BackupBytesPerSec, "c06.s1.backup_create"),
        (MeasurementField::RestoreBytesPerSec, "c06.s5.restore_apply"),
        (
            MeasurementField::RestoreElapsedSeconds,
            "c06.s5.restore_apply",
        ),
        (MeasurementField::RepositoryBytes, "c06.s8.minimum_profile"),
        (
            MeasurementField::DeviceFreeBytesMin,
            "c06.s8.minimum_profile",
        ),
    ])
}

/// `c06MeasureRepositoryBytes` — sum the sizes of the regular files under
/// the root and nothing else: a directory's size is the filesystem's own
/// bookkeeping, a link's is its target's length. Pinned by the portable
/// walker test below over a tree of known sizes.
pub(crate) fn measure_repository_bytes(root: &std::path::Path) -> Result<i64, String> {
    fn walk(dir: &std::path::Path, total: &mut i64) -> Result<(), String> {
        for entry in
            std::fs::read_dir(dir).map_err(|e| format!("measure the backup repository: {e}"))?
        {
            let entry = entry.map_err(|e| format!("measure the backup repository: {e}"))?;
            let file_type = entry
                .file_type()
                .map_err(|e| format!("measure the backup repository: {e}"))?;
            if file_type.is_dir() {
                walk(&entry.path(), total)?;
            } else if file_type.is_file() {
                let info = entry
                    .metadata()
                    .map_err(|e| format!("measure the backup repository: {e}"))?;
                *total += info.len() as i64;
            }
            // Anything else (a symlink) is skipped: its size is the length
            // of its target, not repository content.
        }
        Ok(())
    }
    let mut total = 0i64;
    walk(root, &mut total)?;
    Ok(total)
}

/// `c06MeasureDeviceThroughTheProductionSource` — `f_bavail` through
/// `device_capacity_from_descriptor`, the same arithmetic C02's admission
/// reads.
pub(crate) fn measure_device_through_the_production_source(
    directory: &std::path::Path,
) -> Result<central_backup::backup::capacity::DeviceCapacitySnapshot, String> {
    let dir = std::fs::File::open(directory)
        .map_err(|e| format!("open {} for the device floor: {e}", directory.display()))?;
    central_adapter_linux::backup::device_capacity_from_descriptor(&dir).map_err(|e| {
        format!(
            "measure {} through the production capacity source: {e}",
            directory.display()
        )
    })
}

/// `c06MeasureDeviceFreeFloor` — the smallest free-byte reading across the
/// devices this run used, per device and never their sum.
pub(crate) fn measure_device_free_floor(
    directories: &[(String, std::path::PathBuf)],
    narrator: &mut dyn Narrator,
) -> Result<i64, String> {
    if directories.is_empty() {
        return Err(
            "no directory was offered for the device floor, so the reading would be the minimum of an empty set"
                .to_owned(),
        );
    }
    let mut floor: i64 = -1;
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut roles: Vec<&(String, std::path::PathBuf)> = directories.iter().collect();
    roles.sort_by(|a, b| a.0.cmp(&b.0));
    for (role, directory) in roles {
        let device = measure_device_through_the_production_source(directory)?;
        if device.free_bytes > (1u64 << 62) {
            return Err(format!(
                "the production capacity source reports {} free bytes for the {role} device, which is not a filesystem reading",
                device.free_bytes
            ));
        }
        let free = device.free_bytes as i64;
        if let Some(previous) = seen.get(&device.device_id) {
            narrator.record(format!(
                "the {role} and {previous} roles measure as the SAME opaque device, so the floor below is one filesystem's reading and not the minimum of two"
            ));
        }
        seen.insert(device.device_id.clone(), role.clone());
        narrator.record(format!(
            "device floor input: the {role} role's filesystem reports {free} free bytes through the production capacity source"
        ));
        if floor < 0 || free < floor {
            floor = free;
        }
    }
    Ok(floor)
}

/// `c06MinimumProfileMeasurements` — C06 scenario 8's body.
#[test]
fn c06_s8_minimum_profile() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    let id = "c06.s8.minimum_profile";
    slice_c::scenario(
        id,
        |profile| slice_c::unmet_precondition(id, profile).or_else(scenario2::missing_live_env),
        |_s| {
            let mut log = ScenarioLog::new(id);
            log.recordf(format_args!("{SCENARIO8_SCOPE_DISCLOSURE}"));
            crate::continuous_run::gate_the_sequence("c06.s7.state_equivalence", &mut log)?;
            let mut narrator = ScenarioNarrator { id, log: &mut log };

            // --- 1. The bounds are the installed profile's. --------------
            expect78(
                id,
                "every declared bound is derived from the installed recovery profile, and each is checked in its declared direction",
            );
            profile::verify_declared_bounds_are_the_installed_profiles()?;
            profile::verify_measurement_vocabulary_is_the_emitted_one()?;
            for assertion in profile::minimum_profile_assertions() {
                narrator.record(format!(
                    "assertion {:?} is decided by {:?}",
                    assertion.name, assertion.fields
                ));
            }

            // --- 2. The repository's own size, measured. -----------------
            expect78(
                id,
                "the backup repository's size is measured by walking it, and is not the zero a repository nothing ever sealed into would report",
            );
            let repo_root = scenario2::require_env("CENTRAL_C06_REPO_ROOT")
                .map(std::path::PathBuf::from)
                .ok_or_else(|| {
                    "no repository root is provisioned (CENTRAL_C06_REPO_ROOT); the repository-bytes measurement needs the real repository tree a sealed backup would occupy, and `central backup create` cannot seal on any host while the production composition supplies no throughput gate".to_owned()
                })?;
            let repository_bytes = measure_repository_bytes(&repo_root)?;
            if repository_bytes <= 0 {
                return Err(format!(
                    "the installed instance's backup repository holds {repository_bytes} bytes. A repository of zero bytes satisfies its declared bound trivially, so this is an absent measurement and not a passing one: no backup has been sealed into it. `central backup create` cannot seal on any host while the production composition supplies no throughput gate"
                ));
            }
            crate::fixture::records().record_minimum_profile_measurement(
                MeasurementField::RepositoryBytes,
                repository_bytes,
            )?;
            narrator.record(format!(
                "measurement repository_bytes: {repository_bytes} observed, bound < {}",
                evidence::BOUND_REPOSITORY_BYTES
            ));

            // --- 3. The device floor, through the production capacity source.
            expect78(
                id,
                "the smallest free-byte reading across the devices this run used is measured through the production capacity source, per device and never aggregated",
            );
            let evidence_dir = crate::fixture::evidence_directory()
                .map_err(|e| format!("resolve the evidence directory for the device floor: {e}"))?;
            let floor = measure_device_free_floor(
                &[
                    ("backup repository".to_owned(), repo_root.clone()),
                    ("evidence directory".to_owned(), evidence_dir),
                ],
                &mut narrator,
            )?;
            if floor <= 0 {
                return Err(format!(
                    "the device floor measured {floor} free bytes; a non-positive reading is not a device with no room, it is a reading that was not taken"
                ));
            }
            crate::fixture::records()
                .record_minimum_profile_measurement(MeasurementField::DeviceFreeBytesMin, floor)?;
            narrator.record(format!(
                "measurement device_free_bytes_min: {floor} observed, bound > {} (the FIXED part of the reserve formula only; admission additionally reserves the run's own projected write, so clearing this bound is not a statement that a given backup would be admitted)",
                evidence::BOUND_DEVICE_FREE_BYTES_MIN
            ));

            // --- 4. The three readings other scenarios take. -------------
            expect78(
                id,
                "the backup rate, the restore rate and the restore elapsed time are present in the record set, each put there by the entry that measured it",
            );
            require_every_minimum_profile_measurement_was_taken(&mut narrator)?;

            // --- 5. The assertions. --------------------------------------
            let names: Vec<&str> = profile::minimum_profile_assertions()
                .iter()
                .map(|a| a.name)
                .collect();
            expect78(
                id,
                format!("each of the minimum-profile assertions holds: {names:?}"),
            );
            let observed = crate::fixture::records().observed.clone();
            profile::verify_minimum_profile_measurements(&observed)?;
            let emitted = profile::measurements_by_field(&evidence::measurements_from(&observed));
            let producers = minimum_profile_producers();
            for field in MEASUREMENT_FIELDS {
                if let Some(measurement) = emitted.get(field.as_str()) {
                    narrator.record(format!(
                        "measurement {}: {} observed, bound {} {}, taken by {}",
                        field.as_str(),
                        measurement.observed,
                        measurement.relation,
                        measurement.bound,
                        producers.get(&field).copied().unwrap_or("<no producer>")
                    ));
                }
            }
            Ok(())
        },
    );
}

/// `c06RequireEveryMinimumProfileMeasurementWasTaken` — names the entry
/// that should have produced each absent reading, because a missing backup
/// rate is a defect of the backup path, not of the profile.
fn require_every_minimum_profile_measurement_was_taken(
    narrator: &mut dyn Narrator,
) -> Result<(), String> {
    let producers = minimum_profile_producers();
    let mut absent = Vec::new();
    {
        let records = crate::fixture::records();
        for field in MEASUREMENT_FIELDS {
            let observed = records.minimum_profile_observation(field)?;
            if observed > 0 {
                narrator.record(format!(
                    "measurement {} was taken by {}: {observed}",
                    field.as_str(),
                    producers.get(&field).copied().unwrap_or("<no producer>")
                ));
            } else {
                absent.push(format!(
                    "{} (taken by {})",
                    field.as_str(),
                    producers.get(&field).copied().unwrap_or("<no producer>")
                ));
            }
        }
    }
    if absent.is_empty() {
        return Ok(());
    }
    absent.sort();
    Err(format!(
        "{} of the five minimum-profile measurements were never taken: {}. Each is reported here as ABSENT rather than checked against its bound, because two of the five bounds are upper bounds that a zero satisfies -- a run that measured nothing would otherwise report four met assertions. Every field now has a producing entry, so an absence is a defect of the entry named beside it, not designed behaviour",
        absent.len(),
        absent.join(", ")
    ))
}

// ---------------------------------------------------------------------------
// The portable guards.
// ---------------------------------------------------------------------------

/// `TestC06TheRestoreAuditTablesLeaveBothSidesOfTheEquality` — SC-DEF-83:
/// the audit set is exactly the three restore-act relations, the equality
/// holds them out of both sides, and the content exemption unions them in.
#[test]
fn the_restore_audit_tables_leave_both_sides_of_the_equality() {
    let audit = restore_audit_tables();
    assert_eq!(
        audit,
        [
            "central.recovery_operations",
            "central.recovery_quarantines",
            "central.recovery_bootstrap_registrations"
        ],
        "the restore-audit set must be exactly the three restore-act relations in order"
    );
    let moved = vec![
        "central.epoch_markers".to_owned(),
        "central.recovery_operations".to_owned(),
        "central.recovery_quarantines".to_owned(),
        "central.workspaces".to_owned(),
    ];
    let footprint = vec![
        "central.bootstrap_generations".to_owned(),
        "central.epoch_markers".to_owned(),
        "central.recovery_bootstrap_registrations".to_owned(),
        "central.recovery_operations".to_owned(),
        "central.workspaces".to_owned(),
    ];
    assert_eq!(
        without_restore_audit_tables(&moved),
        vec!["central.epoch_markers", "central.workspaces"]
    );
    assert_eq!(
        without_restore_audit_tables(&footprint),
        vec![
            "central.bootstrap_generations",
            "central.epoch_markers",
            "central.workspaces"
        ]
    );
    assert_eq!(
        with_restore_audit_tables(&footprint),
        vec![
            "central.bootstrap_generations",
            "central.epoch_markers",
            "central.recovery_bootstrap_registrations",
            "central.recovery_operations",
            "central.workspaces",
            "central.recovery_quarantines"
        ]
    );
    assert!(
        !name_set_difference(
            &without_restore_audit_tables(&moved),
            &without_restore_audit_tables(&footprint)
        )
        .is_empty(),
        "the sample moved/footprint pair must keep the bootstrap_generations difference after the audit holdout"
    );
}

/// `TestC06TheStateEquivalenceAxesCoverEveryFieldTheComparisonReports` —
/// every axis the comparison can report must be exercised by some
/// perturbation row, and every declared axis must be one the comparison
/// reports; the same-length claim must be made by exactly one row, in
/// prose AND in flag.
#[test]
fn the_state_equivalence_axes_cover_every_field_the_comparison_reports() {
    let required = axes_the_comparison_can_report();
    let perturbations = state_equivalence_perturbations();
    assert!(!perturbations.is_empty(), "the perturbation table is empty");
    let mut exercised: HashMap<EquivalenceAxis, usize> = HashMap::new();
    let mut say_it_in_prose = Vec::new();
    let mut mark_it_as_done = Vec::new();
    for perturbation in &perturbations {
        assert!(
            !perturbation.axes.is_empty(),
            "perturbation {:?} declares no axis, so nothing holds it to moving one",
            perturbation.name
        );
        for axis in perturbation.axes {
            *exercised.entry(*axis).or_default() += 1;
        }
        if perturbation.name.contains("same length") {
            say_it_in_prose.push(perturbation.name);
        }
        if perturbation.same_length_streamed_body {
            mark_it_as_done.push(perturbation.name);
        }
    }
    for axis in &required {
        if *exercised.get(axis).unwrap_or(&0) == 0 {
            panic!(
                "{} is a field the comparison reports and no perturbation moves it; a restore that lost exactly that would compare equal and nothing here would have shown it",
                axis.as_str()
            );
        }
    }
    for axis in exercised.keys() {
        assert!(
            required.contains(axis),
            "{} is exercised by the perturbation table and is not an axis the comparison reports",
            axis.as_str()
        );
    }
    say_it_in_prose.sort();
    mark_it_as_done.sort();
    assert_eq!(
        mark_it_as_done.len(),
        1,
        "{:?} carry the same-length streamed-body marker, want exactly 1",
        mark_it_as_done
    );
    assert_eq!(
        say_it_in_prose, mark_it_as_done,
        "the perturbations whose NAME claims a same-length change are {say_it_in_prose:?} and the ones MARKED as making it are {mark_it_as_done:?}"
    );
}

/// `c06AttributionProbeFingerprint` — a synthetic base fingerprint for
/// the portable attribution guard.
fn attribution_probe_fingerprint() -> StateFingerprint {
    let digest = |seed: u8| crate::hex_lower(sha2::Sha256::digest([seed; 1]));
    StateFingerprint {
        tables: vec![
            fingerprint::TableFingerprint {
                name: "central.alpha".to_owned(),
                row_count: 10,
                content_sha256: digest(1),
                schema_sha256: digest(2),
            },
            fingerprint::TableFingerprint {
                name: "central.beta".to_owned(),
                row_count: 20,
                content_sha256: digest(3),
                schema_sha256: digest(4),
            },
        ],
        artifacts: vec![ArtifactFingerprint {
            id: "00000000-0000-7000-8000-000000000001".to_owned(),
            size_bytes: 4096,
            body_sha256: digest(5),
            streamed: false,
            metadata_sha256: digest(6),
        }],
        schema_objects: vec![
            fingerprint::SchemaObjectFingerprint {
                name: "probe_a()".to_owned(),
                kind: "function".to_owned(),
                definition_sha256: digest(7),
            },
            fingerprint::SchemaObjectFingerprint {
                name: "probe_b()".to_owned(),
                kind: "function".to_owned(),
                definition_sha256: digest(8),
            },
        ],
    }
}

/// `TestC06TheAxisAttributionIsTheComparisonsOwn` — one axis moved at a
/// time must be attributed to exactly that axis and no other, for every
/// axis the comparison can report.
#[test]
fn the_axis_attribution_is_the_comparisons_own() {
    type AxisMover = Box<dyn Fn(&mut StateFingerprint)>;
    let repeat = |byte: u8| crate::hex_lower(sha2::Sha256::digest([byte; 32]));
    let base = attribution_probe_fingerprint();
    let movers: Vec<(EquivalenceAxis, AxisMover)> = vec![
        (
            EquivalenceAxis::TableRowCount,
            Box::new(|f| f.tables[0].row_count += 7),
        ),
        (
            EquivalenceAxis::TableContent,
            Box::new(move |f| f.tables[0].content_sha256 = repeat(b'b')),
        ),
        (
            EquivalenceAxis::TableSchema,
            Box::new(move |f| f.tables[0].schema_sha256 = repeat(b'c')),
        ),
        (
            EquivalenceAxis::TablePresence,
            Box::new(|f| {
                f.tables.pop();
            }),
        ),
        (
            EquivalenceAxis::ArtifactSize,
            Box::new(|f| f.artifacts[0].size_bytes -= 101),
        ),
        (
            EquivalenceAxis::ArtifactBody,
            Box::new(move |f| f.artifacts[0].body_sha256 = repeat(b'd')),
        ),
        (
            EquivalenceAxis::ArtifactStreamed,
            Box::new(|f| f.artifacts[0].streamed = !f.artifacts[0].streamed),
        ),
        (
            EquivalenceAxis::ArtifactMetadata,
            Box::new(move |f| f.artifacts[0].metadata_sha256 = repeat(b'e')),
        ),
        (
            EquivalenceAxis::ArtifactPresence,
            Box::new(move |f| {
                f.artifacts.push(ArtifactFingerprint {
                    id: "00000000-0000-7000-8000-0000000000ff".to_owned(),
                    size_bytes: 8,
                    body_sha256: repeat(b'6'),
                    streamed: false,
                    metadata_sha256: repeat(b'7'),
                });
            }),
        ),
        (
            EquivalenceAxis::SchemaObjectDefn,
            Box::new(move |f| f.schema_objects[0].definition_sha256 = repeat(b'8')),
        ),
        (
            EquivalenceAxis::SchemaObjectPresence,
            Box::new(|f| {
                f.schema_objects.pop();
            }),
        ),
    ];
    let required = axes_the_comparison_can_report();
    for axis in &required {
        assert!(
            movers.iter().any(|(a, _)| a == axis),
            "no probe mover exists for {}, so the attribution of that axis is never exercised",
            axis.as_str()
        );
    }
    assert_eq!(
        movers.len(),
        required.len(),
        "the movers cover {:?} axes and the comparison reports {:?}; an axis with no mover is an axis this guard silently never builds a pair for",
        movers.iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>(),
        required.iter().map(|a| a.as_str()).collect::<Vec<_>>()
    );
    for (axis, apply) in &movers {
        let mut perturbed = base.clone();
        apply(&mut perturbed);
        let attributed = axes_the_comparison_attributes(&base, &perturbed).unwrap_or_else(|e| {
            panic!(
                "the attribution refused a single-axis change to {}: {e}",
                axis.as_str()
            )
        });
        assert_eq!(
            attributed,
            vec![*axis],
            "moving {} must be attributed to exactly that axis; got {:?}",
            axis.as_str(),
            attributed.iter().map(|a| a.as_str()).collect::<Vec<_>>()
        );
    }
}

/// `TestC06TheRepositoryWalkerMeasuresTheTreeItIsGiven` — a tree of known
/// sizes must measure to exactly their sum, regular files only.
#[test]
fn the_repository_walker_measures_the_tree_it_is_given() {
    let dir = std::env::temp_dir().join(format!("c06-repo-walk-{}", Uuid::now_v7()));
    std::fs::create_dir_all(dir.join("nested/deeper")).unwrap();
    std::fs::write(dir.join("a"), vec![0u8; 100]).unwrap();
    std::fs::write(dir.join("nested/b"), vec![0u8; 20]).unwrap();
    std::fs::write(dir.join("nested/deeper/c"), vec![0u8; 3]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let _ = symlink(dir.join("a"), dir.join("a-link"));
    }
    let measured = measure_repository_bytes(&dir).expect("walk the known tree");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(measured, 123, "regular files only, summed, links skipped");
    let empty = std::env::temp_dir().join(format!("c06-repo-empty-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&empty).unwrap();
    assert_eq!(
        measure_repository_bytes(&empty).unwrap(),
        0,
        "an empty tree measures to zero — the live check then refuses it as not measured"
    );
    let _ = std::fs::remove_dir_all(&empty);
}

/// `TestC06TheDeviceFloorIsAMinimumAndNeverASum` — the floor is the
/// smallest per-device reading, which a sum would mask.
#[test]
fn the_device_floor_is_a_minimum_and_never_a_sum() {
    struct Quiet;
    impl Narrator for Quiet {
        fn expect(&mut self, _what: &str) {}
        fn record(&mut self, _what: String) {}
    }
    let mut quiet = Quiet;
    let dir = std::env::temp_dir();
    let floor = measure_device_free_floor(&[("only device".to_owned(), dir.clone())], &mut quiet)
        .expect("measure the temp device");
    assert!(
        floor > 0,
        "a real filesystem reports a positive free reading"
    );
    assert!(
        measure_device_free_floor(&[], &mut quiet).is_err(),
        "the floor of an empty set must be refused, not reported as zero or a huge default"
    );
}

/// `TestC06TheMinimumProfileRecorderWritesEveryFieldTheEmitterCarries` —
/// every emitted field has a recorder path, a non-positive reading is
/// refused, and a second reading is refused.
#[test]
fn the_minimum_profile_recorder_writes_every_field_the_emitter_carries() {
    let mut records = crate::fixture::RecordSet::default();
    for field in MEASUREMENT_FIELDS {
        assert!(
            records.check_minimum_profile_measurement(field, 42).is_ok(),
            "the recorder must accept a positive reading for {}",
            field.as_str()
        );
        assert!(
            records.check_minimum_profile_measurement(field, 0).is_err(),
            "a zero reading for {} must be refused as not taken",
            field.as_str()
        );
        assert!(
            records
                .check_minimum_profile_measurement(field, -3)
                .is_err(),
            "a negative reading for {} must be refused",
            field.as_str()
        );
        records
            .record_minimum_profile_measurement(field, 42)
            .expect("record the first reading");
        assert!(
            records
                .record_minimum_profile_measurement(field, 43)
                .is_err(),
            "a second reading for {} must be refused — the first is not recoverable",
            field.as_str()
        );
        assert_eq!(
            records.minimum_profile_observation(field).unwrap(),
            42,
            "the field the emitter carries must hold the recorded value"
        );
    }
}

/// `TestC06EveryMinimumProfileFieldHasAProducer` — every emitted
/// measurement field names the catalogue entry that produces it, and that
/// entry exists in the catalogue.
#[test]
fn every_minimum_profile_field_has_a_producer() {
    let producers = minimum_profile_producers();
    for field in MEASUREMENT_FIELDS {
        let producer = producers
            .get(&field)
            .unwrap_or_else(|| panic!("{} has no producing entry", field.as_str()));
        let entry = crate::catalogue::lookup(producer).unwrap_or_else(|| {
            panic!("{producer} produces {field:?} but the catalogue does not declare it")
        });
        assert_eq!(
            entry.kind,
            crate::catalogue::Kind::Scenario,
            "{producer} must be a scenario entry"
        );
    }
    assert_eq!(
        producers.len(),
        MEASUREMENT_FIELDS.len(),
        "a producer outside the emitted five would be a measurement written nowhere"
    );
}
