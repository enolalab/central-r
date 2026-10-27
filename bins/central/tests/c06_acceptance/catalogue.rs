//! `internal/recovery/catalogue.go` — the declared set of C06 entries.
//!
//! Scenarios are declared data, not discovered functions: nothing runs that
//! is not named here, and nothing named here can be quietly dropped, because
//! [`crate::runner::Runner::reconcile`] fails on any entry that ends a run
//! without exactly one outcome. Ported verbatim: ids, packets, attribution,
//! preconditions, required-for-SC-G3 flags and summaries.

use central_backup::backup::operation::BackupPhase;
use central_backup::recovery::operation::{RestoreCheckpoint, RestorePhase};
use sha2::{Digest, Sha256};

/// `Packet` — the Slice C packet a catalogue entry evidences. Closed at the
/// five packets the Slice C plan defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet {
    C01,
    C02,
    C03,
    C04,
    C05,
}

impl Packet {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C01 => "C01",
            Self::C02 => "C02",
            Self::C03 => "C03",
            Self::C04 => "C04",
            Self::C05 => "C05",
        }
    }
}

/// `AttributionSource` — whether the C06 packet list named this packet
/// (`packet_list`) or this catalogue derived it by subject (`by_subject`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributionSource {
    PacketList,
    BySubject,
}

impl AttributionSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PacketList => "packet_list",
            Self::BySubject => "by_subject",
        }
    }
}

/// `Kind` separates a numbered scenario from a restart injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Scenario,
    RestartInjection,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scenario => "scenario",
            Self::RestartInjection => "restart_injection",
        }
    }
}

/// `ReasonClass` — the closed vocabulary a skip is filed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonClass {
    NotRoot,
    NoPhysicalTty,
    NoPamStack,
    ToolAbsent,
    DockerAbsent,
    PreconditionFailed,
    NotArmed,
}

impl ReasonClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRoot => "not_root",
            Self::NoPhysicalTty => "no_physical_tty",
            Self::NoPamStack => "no_pam_stack",
            Self::ToolAbsent => "tool_absent",
            Self::DockerAbsent => "docker_absent",
            Self::PreconditionFailed => "precondition_failed",
            Self::NotArmed => "not_armed",
        }
    }

    /// `ReasonClasses` — the whole closed vocabulary.
    pub const ALL: [ReasonClass; 7] = [
        Self::NotRoot,
        Self::NoPhysicalTty,
        Self::NoPamStack,
        Self::ToolAbsent,
        Self::DockerAbsent,
        Self::PreconditionFailed,
        Self::NotArmed,
    ];
}

/// `Preconditions` — bitset of environmental facts an entry needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preconditions(pub u8);

impl Preconditions {
    pub const ROOT: Self = Self(1 << 0);
    pub const PHYSICAL_TTY: Self = Self(1 << 1);
    pub const PAM: Self = Self(1 << 2);
    pub const PG_TOOLS: Self = Self(1 << 3);
    pub const DOCKER: Self = Self(1 << 4);

    pub const ALL: Self =
        Self(Self::ROOT.0 | Self::PHYSICAL_TTY.0 | Self::PAM.0 | Self::PG_TOOLS.0 | Self::DOCKER.0);

    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `Has` — every bit of `want` set in `self`.
    pub const fn has(self, want: Self) -> bool {
        self.0 & want.0 == want.0
    }

    /// `Names` — declared names of set bits, in declaration order.
    pub fn names(self) -> Vec<&'static str> {
        PRECONDITION_NAMES
            .iter()
            .filter(|p| self.0 & p.bit.0 != 0)
            .map(|p| p.name)
            .collect()
    }
}

struct PreconditionName {
    bit: Preconditions,
    name: &'static str,
    class: ReasonClass,
}

/// `preconditionNames`, in the order the plan lists them.
const PRECONDITION_NAMES: [PreconditionName; 5] = [
    PreconditionName {
        bit: Preconditions::ROOT,
        name: "root",
        class: ReasonClass::NotRoot,
    },
    PreconditionName {
        bit: Preconditions::PHYSICAL_TTY,
        name: "physical_tty",
        class: ReasonClass::NoPhysicalTty,
    },
    PreconditionName {
        bit: Preconditions::PAM,
        name: "pam",
        class: ReasonClass::NoPamStack,
    },
    PreconditionName {
        bit: Preconditions::PG_TOOLS,
        name: "pg_tools",
        class: ReasonClass::ToolAbsent,
    },
    PreconditionName {
        bit: Preconditions::DOCKER,
        name: "docker",
        class: ReasonClass::DockerAbsent,
    },
];

/// `ReasonClassForUnmet` — maps a single unmet bit to its census class;
/// refuses zero or more-than-one bit.
pub fn reason_class_for_unmet(unmet: Preconditions) -> Option<ReasonClass> {
    if unmet.0 == 0 || unmet.0 & (unmet.0 - 1) != 0 {
        return None;
    }
    PRECONDITION_NAMES
        .iter()
        .find(|p| p.bit.0 == unmet.0)
        .map(|p| p.class)
}

/// `Entry` — one declared unit of C06 work.
#[derive(Debug, Clone)]
pub struct Entry {
    pub id: &'static str,
    pub packet: Packet,
    pub attribution: AttributionSource,
    pub kind: Kind,
    /// The durable boundary a restart injection interrupts; empty for
    /// scenarios. Values come from the domain's own wire constants.
    pub boundary: &'static str,
    pub preconditions: Preconditions,
    pub required_for_scg3: bool,
    /// One-line, locator-free description for the run report.
    pub summary: &'static str,
}

// Boundary spellings, in "<domain>:<state>" form, composed from the domain's
// wire constants so the catalogue cannot drift from what the journal writes.
fn backup_boundary(phase: BackupPhase) -> String {
    format!("backup:{}", phase.as_str())
}

/// `installedCatalogue` — the single declaration of everything C06 owns,
/// ported entry-for-entry. Every entry is `required_for_scg3`.
pub fn installed_catalogue() -> Vec<Entry> {
    let p_root_pg_docker = Preconditions::ROOT
        .or(Preconditions::PG_TOOLS)
        .or(Preconditions::DOCKER);
    let p_full = p_root_pg_docker
        .or(Preconditions::PHYSICAL_TTY)
        .or(Preconditions::PAM);
    // Leak the domain-composed boundary strings once — the catalogue is a
    // process-lifetime constant, exactly as upstream's declaration is.
    let b = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    vec![
        Entry {
            id: "c06.s1.backup_create",
            packet: Packet::C01,
            attribution: AttributionSource::PacketList,
            kind: Kind::Scenario,
            boundary: "",
            preconditions: p_root_pg_docker,
            required_for_scg3: true,
            summary: "create a backup; the manifest is signed and the dump verified",
        },
        Entry {
            id: "c06.s2.corruption_detected",
            packet: Packet::C03,
            attribution: AttributionSource::BySubject,
            kind: Kind::Scenario,
            boundary: "",
            preconditions: p_root_pg_docker,
            required_for_scg3: true,
            summary: "inject database row deletion and each object-corruption shape; the application detects the inconsistency through its own path",
        },
        Entry {
            id: "c06.s3.restore_verify",
            packet: Packet::C03,
            attribution: AttributionSource::PacketList,
            kind: Kind::Scenario,
            boundary: "",
            preconditions: p_root_pg_docker,
            required_for_scg3: true,
            summary: "restore verify admits the sealed backup through the real operator surface",
        },
        Entry {
            id: "c06.s4.restore_ticket_one_use",
            packet: Packet::C03,
            attribution: AttributionSource::PacketList,
            kind: Kind::Scenario,
            boundary: "",
            preconditions: p_root_pg_docker,
            required_for_scg3: true,
            summary: "the restore ticket is recorded and one-use; replay, expiry, hash mismatch and target mismatch are refused",
        },
        Entry {
            id: "c06.s5.restore_apply",
            packet: Packet::C04,
            attribution: AttributionSource::PacketList,
            kind: Kind::Scenario,
            boundary: "",
            preconditions: p_full,
            required_for_scg3: true,
            summary: "restore apply quarantines, restores and reaches a fresh bootstrap under the real PAM and physical-TTY ceremony",
        },
        Entry {
            id: "c06.s6.authority_reset",
            packet: Packet::C05,
            attribution: AttributionSource::PacketList,
            kind: Kind::Scenario,
            boundary: "",
            preconditions: p_full,
            required_for_scg3: true,
            summary: "the post-restore authority reset advances the epochs, invalidates prior authority and rekeys broker TLS",
        },
        Entry {
            id: "c06.s7.state_equivalence",
            packet: Packet::C04,
            attribution: AttributionSource::BySubject,
            kind: Kind::Scenario,
            boundary: "",
            preconditions: p_full,
            required_for_scg3: true,
            summary: "post-restore state matches the pre-corruption fingerprint and differs from the post-corruption one",
        },
        Entry {
            id: "c06.s8.minimum_profile",
            packet: Packet::C02,
            attribution: AttributionSource::BySubject,
            kind: Kind::Scenario,
            boundary: "",
            preconditions: p_full,
            required_for_scg3: true,
            summary: "backup throughput, restore throughput, disk usage and restore time each measured against their declared bound",
        },
        Entry {
            id: "c06.s9.capacity_below_floor",
            packet: Packet::C02,
            attribution: AttributionSource::PacketList,
            kind: Kind::Scenario,
            boundary: "",
            preconditions: p_root_pg_docker,
            required_for_scg3: true,
            summary: "a below-floor device makes backup creation refuse before any mutation, from the production admission path",
        },
        Entry {
            id: "c06.s10.throughput_below_floor",
            packet: Packet::C02,
            attribution: AttributionSource::PacketList,
            kind: Kind::Scenario,
            boundary: "",
            preconditions: p_root_pg_docker,
            required_for_scg3: true,
            summary: "a genuinely slow device produces the typed outside-profile result the production path actually returns, with the divergence from the packet's wording recorded",
        },
        Entry {
            id: "c06.r1.restart_backup_admitted",
            packet: Packet::C01,
            attribution: AttributionSource::BySubject,
            kind: Kind::RestartInjection,
            boundary: b(backup_boundary(BackupPhase::Admitted)),
            preconditions: p_root_pg_docker,
            required_for_scg3: true,
            summary: "restart at the admitted backup boundary; a new operation is required and the evidence survived",
        },
        Entry {
            id: "c06.r2.restart_backup_dumping",
            packet: Packet::C01,
            attribution: AttributionSource::BySubject,
            kind: Kind::RestartInjection,
            boundary: b(backup_boundary(BackupPhase::Dumping)),
            preconditions: p_root_pg_docker,
            required_for_scg3: true,
            summary: "restart at the dumping backup boundary; no duplicate seal, and the evidence survived",
        },
        Entry {
            id: "c06.r3.restart_backup_inventory",
            packet: Packet::C01,
            attribution: AttributionSource::BySubject,
            kind: Kind::RestartInjection,
            boundary: b(backup_boundary(BackupPhase::Inventory)),
            preconditions: p_root_pg_docker,
            required_for_scg3: true,
            summary: "restart at the inventory backup boundary; no duplicate seal, and the evidence survived",
        },
        Entry {
            id: "c06.r4.restart_backup_sealing",
            packet: Packet::C01,
            attribution: AttributionSource::BySubject,
            kind: Kind::RestartInjection,
            boundary: b(backup_boundary(BackupPhase::Sealing)),
            preconditions: p_root_pg_docker,
            required_for_scg3: true,
            summary: "restart at the sealing backup boundary; no duplicate seal, and the evidence survived",
        },
        Entry {
            id: "c06.r5.restart_ticket_consumed",
            packet: Packet::C04,
            attribution: AttributionSource::BySubject,
            kind: Kind::RestartInjection,
            boundary: b(RestoreCheckpoint::TicketConsumed.as_str().to_owned()),
            preconditions: p_full,
            required_for_scg3: true,
            summary: "restart after the ticket is consumed; no partial serve, no ticket replay, no surviving pre-restore authority",
        },
        Entry {
            id: "c06.r6.restart_database_replaced",
            packet: Packet::C04,
            attribution: AttributionSource::BySubject,
            kind: Kind::RestartInjection,
            boundary: b(RestoreCheckpoint::DatabaseReplaced.as_str().to_owned()),
            preconditions: p_full,
            required_for_scg3: true,
            summary: "restart after the database is replaced; no partial serve, and the operation resumes rather than restarting",
        },
        Entry {
            id: "c06.r7.restart_inventory_verified",
            packet: Packet::C04,
            attribution: AttributionSource::BySubject,
            kind: Kind::RestartInjection,
            boundary: b(RestoreCheckpoint::InventoryVerified.as_str().to_owned()),
            preconditions: p_full,
            required_for_scg3: true,
            summary: "restart after inventory verification; no Artifact delivery from quarantine",
        },
        Entry {
            id: "c06.r8.restart_authority_reset",
            packet: Packet::C05,
            attribution: AttributionSource::BySubject,
            kind: Kind::RestartInjection,
            boundary: b(RestoreCheckpoint::AuthorityReset.as_str().to_owned()),
            preconditions: p_full,
            required_for_scg3: true,
            summary: "restart after the authority reset; no pre-restore session, grant or lease survives",
        },
        Entry {
            id: "c06.r9.restart_restore_abandoned",
            packet: Packet::C04,
            attribution: AttributionSource::BySubject,
            kind: Kind::RestartInjection,
            boundary: b(format!("restore:{}", RestorePhase::Abandoned.as_str())),
            preconditions: p_full,
            required_for_scg3: true,
            summary: "restart after an abandonment authorized by its own ceremony; the operation neither resumes nor serves, and the abandonment is irreversible",
        },
    ]
}

/// `Lookup`.
pub fn lookup(id: &str) -> Option<Entry> {
    installed_catalogue().into_iter().find(|e| e.id == id)
}

/// `Index` — declaration position of `id`, or -1.
pub fn index_of(id: &str) -> i64 {
    installed_catalogue()
        .iter()
        .position(|e| e.id == id)
        .map(|p| p as i64)
        .unwrap_or(-1)
}

/// `Scenarios` / `RestartInjections`.
pub fn of_kind(kind: Kind) -> Vec<Entry> {
    installed_catalogue()
        .into_iter()
        .filter(|e| e.kind == kind)
        .collect()
}

/// `CatalogueDigest` — sha-256 over `id\tkind\trequired_for_sc_g3\n` records
/// in declaration order.
pub fn catalogue_digest(catalogue: &[Entry]) -> String {
    let mut hash = Sha256::new();
    for entry in catalogue {
        hash.update(
            format!(
                "{}\t{}\t{}\n",
                entry.id,
                entry.kind.as_str(),
                entry.required_for_scg3
            )
            .as_bytes(),
        );
    }
    crate::hex_lower(hash.finalize())
}

/// `Validate` — every structural problem in the catalogue at once.
pub fn validate(catalogue: &[Entry]) -> Result<(), String> {
    let mut problems: Vec<String> = Vec::new();
    let mut seen = std::collections::HashMap::<&str, usize>::new();
    for entry in catalogue {
        *seen.entry(entry.id).or_default() += 1;
        if entry.id.trim().is_empty() {
            problems.push("an entry has an empty ID".to_owned());
            continue;
        }
        if seen[entry.id] == 2 {
            problems.push(format!("{} is declared more than once", entry.id));
        }
        // Packet/attribution/kind are closed Rust enums — their `Valid()`
        // checks are unrepresentable states rather than runtime checks.
        if entry.kind == Kind::RestartInjection && entry.boundary.is_empty() {
            problems.push(format!("{} is a restart injection with no durable boundary; governance field 23 is a completeness claim over the boundary enumeration", entry.id));
        }
        if entry.kind == Kind::Scenario && !entry.boundary.is_empty() {
            problems.push(format!(
                "{} is a scenario carrying boundary {:?}; only restart injections name a boundary",
                entry.id, entry.boundary
            ));
        }
        if entry.preconditions.0 & !Preconditions::ALL.0 != 0 {
            problems.push(format!(
                "{} sets a precondition bit outside the declared bitset",
                entry.id
            ));
        }
        if entry.summary.trim().is_empty() {
            problems.push(format!("{} has no summary", entry.id));
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(format!(
        "recovery: the C06 catalogue is invalid:\n  - {}",
        problems.join("\n  - ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_installed_catalogue_validates() {
        validate(&installed_catalogue()).expect("installed catalogue must validate");
    }

    #[test]
    fn the_catalogue_names_every_enumerated_restart_boundary() {
        let catalogue = installed_catalogue();
        let boundaries: Vec<&str> = catalogue
            .iter()
            .filter(|e| e.kind == Kind::RestartInjection)
            .map(|e| e.boundary)
            .collect();
        // Governance field 23's eight durable boundaries, plus r9's
        // abandonment injection (ADR 0016), each named exactly once.
        for want in [
            "backup:admitted",
            "backup:dumping",
            "backup:inventory",
            "backup:sealing",
            "ticket_consumed",
            "database_replaced",
            "inventory_verified",
            "authority_reset",
            "restore:abandoned",
        ] {
            assert!(
                boundaries.contains(&want),
                "missing restart boundary {want}"
            );
        }
        assert_eq!(boundaries.len(), 9);
    }

    #[test]
    fn reason_class_for_unmet_refuses_ambiguity() {
        assert_eq!(
            reason_class_for_unmet(Preconditions::ROOT),
            Some(ReasonClass::NotRoot)
        );
        assert_eq!(
            reason_class_for_unmet(Preconditions::PAM),
            Some(ReasonClass::NoPamStack)
        );
        assert!(reason_class_for_unmet(Preconditions(0)).is_none());
        assert!(reason_class_for_unmet(Preconditions::ROOT.or(Preconditions::PAM)).is_none());
    }

    #[test]
    fn the_catalogue_digest_is_stable_and_order_sensitive() {
        let catalogue = installed_catalogue();
        let first = catalogue_digest(&catalogue);
        let second = catalogue_digest(&installed_catalogue());
        assert_eq!(first, second);
        let mut reordered = catalogue;
        reordered.swap(0, 1);
        assert_ne!(catalogue_digest(&reordered), first);
    }

    /// `installedCatalogueDigest` is `catalogue_digest(&installed_catalogue())`
    /// for the catalogue this repository ships, recorded here so that the value
    /// is checkable from committed source: a reader holding an emitted artifact
    /// compares its `catalogue_sha256` against this literal and learns whether
    /// the run covered C06's whole catalogue, without building or running the
    /// suite.
    ///
    /// It is not evidence and it is not an artifact. It is a property of the
    /// suite's own definition, in the same way the ten-scenario and
    /// nine-boundary lists above are.
    ///
    /// Derivable by hand: `catalogue_digest` hashes one
    /// `"id\tkind\trequired_for_sc_g3\n"` record per entry in declaration
    /// order, so
    ///
    /// ```text
    /// printf 'c06.s1.backup_create\tscenario\ttrue\n...' | sha256sum
    /// ```
    ///
    /// over the nineteen entries reproduces it. The value below was recomputed
    /// that way — by piping the nineteen records through `sha256sum` — rather
    /// than by copying what the failing test printed, because a constant
    /// updated from the code it is meant to pin is a constant that agrees with
    /// any code at all. This is the same literal upstream pins at
    /// `catalogue_test.go:145`, and the two implementations must keep agreeing
    /// on it because the emitted artifact's `catalogue_sha256` is the field a
    /// reviewer uses to tell a full run from a narrowed one across both ports.
    const INSTALLED_CATALOGUE_DIGEST: &str =
        "02fa72ee32a743ab753dcea089995d8c3aa8fa4c615888ef25f7a62a67042738";

    /// `TestTheInstalledCatalogueDigestIsTheRecordedValue` pins that literal.
    /// It fails when the catalogue changes and the recorded value does not,
    /// which is the only way the two can drift apart: a published expected
    /// digest that silently stops describing the shipped catalogue is worse
    /// than none, because a reviewer would read a mismatch as a truncated run
    /// rather than as a stale constant.
    ///
    /// It also catches an in-module narrowing of `installed_catalogue`, which
    /// nothing else does in one place — the runner tests that count entries
    /// compare against the declaration itself and are therefore circular.
    #[test]
    fn the_installed_catalogue_digest_is_the_recorded_value() {
        let got = catalogue_digest(&installed_catalogue());
        assert_eq!(
            got, INSTALLED_CATALOGUE_DIGEST,
            "the installed catalogue digests to {got}, but the recorded value is \
             {INSTALLED_CATALOGUE_DIGEST}; if the catalogue changed deliberately, \
             change the recorded value in the same commit — a reviewer checking \
             an artifact's catalogue_sha256 reads this literal"
        );
    }

    /// `TestTheCatalogueDigestDistinguishesEveryFieldItClaimsToCover` holds
    /// `catalogue_digest` to its own coverage claim. The digest is what makes
    /// an emitted artifact self-describing — it is the only field that tells a
    /// full run from a narrowed one — so a regression that quietly stopped
    /// covering one of these fields would leave a materially different
    /// catalogue digesting identically to C06's own, and `catalogue_sha256`
    /// would certify a catalogue it cannot distinguish.
    ///
    /// The edited catalogues below are deliberately not valid: nothing
    /// validates them, and the point is what the digest sees, not what
    /// `validate` would reject.
    #[test]
    fn the_catalogue_digest_distinguishes_every_field_it_claims_to_cover() {
        let baseline = catalogue_digest(&installed_catalogue());

        struct Case {
            name: &'static str,
            reason: &'static str,
            edit: fn(&mut Vec<Entry>),
        }
        let cases = [
            Case {
                name: "a scenario reclassified as a restart injection",
                reason: "the kind decides which manifest field an entry lands in — field 10 for a scenario, field 23 for a restart injection",
                edit: |c: &mut Vec<Entry>| c[0].kind = Kind::RestartInjection,
            },
            Case {
                name: "an entry flipped out of rule E-1's scope",
                reason: "required_for_sc_g3 decides whether a skip of that entry is a gate failure",
                edit: |c: &mut Vec<Entry>| c[0].required_for_scg3 = !c[0].required_for_scg3,
            },
            Case {
                name: "two entries transposed",
                reason: "the digest is over the declaration order, which the census and the emitted scenario list are both built from",
                edit: |c: &mut Vec<Entry>| c.swap(0, 1),
            },
        ];
        for case in &cases {
            let mut edited = installed_catalogue();
            (case.edit)(&mut edited);
            assert_ne!(
                catalogue_digest(&edited),
                baseline,
                "a catalogue differing from the installed one in exactly this way \
                 digests identically; {}, so catalogue_sha256 cannot tell the two \
                 apart (case: {})",
                case.reason,
                case.name
            );
        }

        // Anti-vacuity, and the reason the edits above are safe: every case
        // edits a fresh copy, so a case that appeared to differ because an
        // earlier one mutated the declaration would show up here.
        assert_eq!(
            catalogue_digest(&installed_catalogue()),
            baseline,
            "the installed catalogue's digest changed while this test ran; the \
             cases above edited the declaration rather than a copy, so none of \
             them proves anything"
        );
    }
}
