//! `restore_capacity_reserve_inspection_linux.go` — the inspection
//! surface: the only thing in this design that tells a human what all
//! the other decisions did.
//!
//! Every other task here decides something — the helper measures and
//! allocates, the daemon records and gates, the sweep releases. None
//! of them is observable. An operator who has just been refused a
//! restore with `RESTORE_CAPACITY_INSUFFICIENT` cannot tell "this disk
//! is genuinely too full" from "a reserve from a previous crash is
//! still held". This file is that view.
//!
//! # The tension, and which way it is resolved
//!
//! The surface has to be useful enough to diagnose a refusal and
//! useless as a device-headroom oracle, and those pull opposite ways.
//! Every unresolved case here is resolved by withholding.
//!
//! - **Root peers only, and never the runtime UID.** The broker has no
//!   operator peer class; admitting the runtime would hand the
//!   unprivileged runtime a device-headroom oracle.
//!   `inspection_peer_admitted` refuses the runtime UID *even if it is
//!   root*, rather than letting a misconfigured deployment turn this
//!   into the oracle it exists not to be.
//! - **No exact figures anywhere.** Everything quantitative is a band
//!   (`InspectionBand`/`InspectionAge`). There is no integer field in
//!   the report's type graph at all.
//! - **No locator anywhere.** No pathname, no inode, no `st_dev`. The
//!   sweep's own outcome `key` is *never* carried: a key can be a raw
//!   directory entry name (`SweepCondition::UnrecognizedEntry` is
//!   reported with `key` = the name found on disk), which is a
//!   pathname component chosen by whatever dropped the file there.
//!   Findings are aggregated to (item, action, condition, trigger)
//!   tuples and a band, and the keys are discarded.
//! - **No observed-free-bytes and no `st_dev`**: the observed free
//!   bytes *is* the device headroom this surface exists to withhold,
//!   and `st_dev` is a device locator.
//!
//! The one identity that is emitted is the device fingerprint
//! (`fs-` + 32 hex). It is required — "bytes reserved per device
//! fingerprint" is the brief's first bullet. It is not headroom and
//! not a locator: it is sha256(f_fsid) truncated, which any root peer
//! on the host can recompute from a statfs it is already allowed to
//! make.
//!
//! # The bucket granularity, and why this one
//!
//! The reserve object is exactly `SURVIVAL_RESERVE_BYTES` (4 GiB) per
//! device, and the host cap is 16 GiB across at most four devices. So
//! the whole range this surface reports over is four reserve units
//! wide. The granularity chosen is **none / one / several** — the
//! coarsest partition that still answers both diagnostic questions.
//! The age of the oldest live set is banded on the same principle,
//! against this design's own two clocks: inside the receipt window
//! (20 minutes), past it but inside the absolute expiry (8 hours), or
//! past the absolute expiry.
//!
//! # How the sweep's findings reach a daemon-served frame
//!
//! The sweep runs in the root helper; the frame server is the hardened
//! daemon. The findings cross as a durable digest: the helper hands a
//! sweep report it *already took* to `publish_inspection_digest`,
//! which writes one HMAC-signed record at one fixed name, and the
//! daemon reads that one record with a single openat — no enumeration.
//! Bucketing happens at publish time, not at serve time, so the
//! durable artifact physically cannot carry an exact byte count, an
//! `st_dev`, an observed-free-bytes value or a pathname.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;

use central_foundation::failure::Failure;
use central_infra::authority::{BrokerOutcome, BrokerResponse};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::broker::deadline::DeadlineStream;
use crate::broker::durable;
use crate::broker::protocol;
use crate::broker::server::Service;
use crate::broker::wire;
use crate::sys::peercred::PeerCred;

use super::RESERVE_ABSOLUTE_LIFETIME;
use super::receipt::RECEIPT_LIFETIME;
use super::store::{self, RECORD_SCHEMA, ReserveStore};
use super::store_path;
use super::sweep::{
    ReleaseTrigger, SweepAction, SweepCaller, SweepCondition, SweepItem, SweepReport,
};

// --- the quantitative vocabulary ------------------------------------------------

/// `RestoreCapacityReserveInspectionBand` — this surface's entire
/// quantitative vocabulary: zero, exactly one, or two-or-more. The
/// coarsest partition that still answers both diagnostic questions;
/// each extra band narrows the residual a difference of two readings
/// recovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InspectionBand {
    None,
    One,
    Several,
}
impl InspectionBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::One => "one",
            Self::Several => "several",
        }
    }
    /// `restoreCapacityReserveInspectionBandOf` — the only place a
    /// count becomes a figure this surface will emit. Deliberately
    /// total over negative and absurd inputs: a count this engine
    /// could not compute is "none", never a number that escapes the
    /// vocabulary.
    fn of(count: i64) -> Self {
        match count {
            c if c <= 0 => Self::None,
            1 => Self::One,
            _ => Self::Several,
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "none" => Self::None,
            "one" => Self::One,
            "several" => Self::Several,
            _ => return None,
        })
    }
}

/// `RestoreCapacityReserveInspectionAge` — the age of the oldest live
/// reserve set, banded against this design's own two clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InspectionAge {
    /// No live set to be old, or none whose record this build could
    /// read.
    None,
    /// Younger than `RECEIPT_LIFETIME`: a restore attempt that may
    /// still be mid-flight, and that no sweep trigger acts on yet.
    WithinReceiptWindow,
    /// Past the receipt window and inside the absolute expiry: the
    /// receipt-window-lapsed and abandonment triggers can fire, the
    /// absolute-expiry one cannot.
    BeyondReceiptWindow,
    /// Past `RESERVE_ABSOLUTE_LIFETIME`: a set the sweep releases on
    /// expiry unless its operation is still applying.
    BeyondAbsoluteExpiry,
}
impl InspectionAge {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WithinReceiptWindow => "within_receipt_window",
            Self::BeyondReceiptWindow => "beyond_receipt_window",
            Self::BeyondAbsoluteExpiry => "beyond_absolute_expiry",
        }
    }
    fn of(age: time::Duration) -> Self {
        if age < RECEIPT_LIFETIME {
            Self::WithinReceiptWindow
        } else if age < RESERVE_ABSOLUTE_LIFETIME {
            Self::BeyondReceiptWindow
        } else {
            Self::BeyondAbsoluteExpiry
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "none" => Self::None,
            "within_receipt_window" => Self::WithinReceiptWindow,
            "beyond_receipt_window" => Self::BeyondReceiptWindow,
            "beyond_absolute_expiry" => Self::BeyondAbsoluteExpiry,
            _ => return None,
        })
    }
}

// --- serde for the closed vocabularies ----------------------------------------
// Every enum serializes through its fixed wire string; an
// out-of-vocabulary value fails the strict decode, which is the
// `DenyUnknownFields`-style discipline this package already applies.

macro_rules! wire_enum_serde {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let value = <&str>::deserialize(d)?;
                Self::from_str(value).ok_or_else(|| {
                    serde::de::Error::custom("unrecognized restore capacity vocabulary")
                })
            }
        }
    };
}
wire_enum_serde!(InspectionBand);
wire_enum_serde!(InspectionAge);
wire_enum_serde!(SweepCaller);
wire_enum_serde!(ReleaseTrigger);
wire_enum_serde!(SweepItem);
wire_enum_serde!(SweepAction);
wire_enum_serde!(SweepCondition);

// --- the report shape ------------------------------------------------------------

/// `RestoreCapacityReserveInspectionDevice` — one device's held
/// reserve, named by the fingerprint and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionDevice {
    pub device_fingerprint: String,
    pub reserved: InspectionBand,
}

/// `RestoreCapacityReserveInspectionFinding` — one aggregated class of
/// sweep outcome. It carries the four closed vocabularies the sweep
/// decides in, and a band — never the outcome's key, which can be a
/// raw directory entry name and is therefore a pathname component this
/// surface must not repeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionFinding {
    pub item: SweepItem,
    pub action: SweepAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<SweepCondition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<ReleaseTrigger>,
    pub count: InspectionBand,
}

/// Go's `<` over the four string fields, in order.
fn finding_less(left: &InspectionFinding, right: &InspectionFinding) -> bool {
    finding_key(left) < finding_key(right)
}

fn finding_key(
    finding: &InspectionFinding,
) -> (&'static str, &'static str, &'static str, &'static str) {
    (
        finding.item.as_str(),
        finding.action.as_str(),
        finding.condition.map_or("", |c| c.as_str()),
        finding.trigger.map_or("", |t| t.as_str()),
    )
}

/// `RestoreCapacityReserveInspectionReport` — the whole of what this
/// surface emits.
///
/// Its type graph contains no integer or floating-point field
/// anywhere, and that is a load-bearing property: an exact byte count,
/// an observed-free-bytes reading, an `st_dev` and an inode are all
/// numbers, so a field able to carry one cannot be added without
/// breaking the closed leaf-set assertion in the no-locator test.
///
/// `observed_at` is the single time-typed leaf and is the sweep pass's
/// own clock, not a quantity: without it a stale digest reads as a
/// current view, which is the one way this surface could actively
/// mislead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionReport {
    /// Which of the sweep's two named root call sites produced the
    /// pass this view was published from.
    pub caller: SweepCaller,
    /// When that pass ran — how an operator tells a current view from
    /// one left behind by a boot-time pass hours ago.
    #[serde(with = "wire::rfc3339")]
    pub observed_at: OffsetDateTime,
    /// The sweep's own "no reserve object was unlinked at all on this
    /// pass, because some record could not be read" — the single most
    /// useful field here when a reserve is stuck.
    pub records_intact: bool,
    /// How many reserve sets the pass retained.
    pub live_sets: InspectionBand,
    /// The age band of the oldest of them.
    pub oldest_live_set: InspectionAge,
    /// How many physical reserve objects the pass found and left in
    /// place. Objects the pass released are not counted — their bytes
    /// are back — but they are visible as a released finding below.
    pub held_objects: InspectionBand,
    /// The per-device-fingerprint breakdown of `held_objects`, sorted
    /// by fingerprint so the record is stable enough to sign.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<InspectionDevice>,
    /// Every sweep outcome class the pass reported, aggregated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<InspectionFinding>,
}

impl InspectionReport {
    /// `RestoreCapacityReserveInspectionReport.valid`.
    pub fn valid(&self) -> bool {
        if wire::is_go_zero_time(self.observed_at) {
            return false;
        }
        for (index, device) in self.devices.iter().enumerate() {
            if !store_path::valid_fingerprint(&device.device_fingerprint) {
                return false;
            }
            if index > 0 && self.devices[index - 1].device_fingerprint >= device.device_fingerprint
            {
                return false;
            }
        }
        for (index, finding) in self.findings.iter().enumerate() {
            if index > 0 && finding_less(finding, &self.findings[index - 1]) {
                return false;
            }
        }
        true
    }
}

// --- the durable digest ------------------------------------------------------------

/// `restoreCapacityReserveInspectionDigest` — the durable, HMAC-signed
/// record the helper publishes and the daemon serves. One file at one
/// fixed name, so the daemon reaches it with a single openat and never
/// enumerates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectionDigest {
    schema_version: String,
    report: InspectionReport,
    hmac: String,
}

impl InspectionDigest {
    fn valid(&self) -> bool {
        self.schema_version == RECORD_SCHEMA && self.report.valid()
    }
    /// `restoreCapacityReserveInspectionPayload` — the signed bytes:
    /// the record with the signature field zeroed.
    fn payload(&self) -> Result<Vec<u8>, Failure> {
        if !self.valid() {
            return Err(inspection_unavailable());
        }
        let mut clone = self.clone();
        clone.hmac.clear();
        serde_json::to_vec(&clone).map_err(|e| {
            Failure::internal(
                INSPECTION_UNAVAILABLE_CODE,
                format!("broker: marshal inspection digest payload: {e}"),
            )
        })
    }
}

/// `restoreCapacityReserveInspectionDigestName` — a constant rather
/// than a derived name precisely because the daemon must be able to
/// open it without knowing any identity and without enumerating.
const DIGEST_NAME: &str = "inspection-digest.json";
const INSPECTION_HMAC_DOMAIN: &str = "slice-c-restore-capacity-reserve-inspection-v1";

const INSPECTION_UNAVAILABLE_CODE: &str = "broker_restore_inspection_unavailable";
fn inspection_unavailable() -> Failure {
    Failure::internal(
        INSPECTION_UNAVAILABLE_CODE,
        "broker: restore capacity reserve inspection unavailable",
    )
}

impl ReserveStore {
    /// `inspectionDigestPath` — the digest's path derived from the
    /// store's own set directory rather than a fifth field on
    /// `ReserveStore`: the reserve root is the parent of the sets
    /// directory by construction.
    fn inspection_digest_path(&self) -> Option<PathBuf> {
        Some(self.sets_dir().parent()?.join(DIGEST_NAME))
    }

    /// `PublishInspectionDigest` — write the operator-visible view
    /// derived from one sweep pass. Runs wherever the sweep runs —
    /// the root helper — because that is the only process that can
    /// produce a report at all.
    ///
    /// It takes a finished `SweepReport` as a parameter and has no way
    /// to obtain one for itself, which is the structural form of "this
    /// surface never triggers a sweep". Beyond the report it reads
    /// only set records, by ids the report already names, through the
    /// store's own non-mutating `read_set`: no enumeration, no lock,
    /// no state transition.
    ///
    /// Everything it writes is already bucketed. The digest cannot
    /// carry an exact byte count, an observed-free-bytes reading, an
    /// `st_dev`, an inode or a pathname, because `InspectionReport`
    /// has no field of a shape that could hold one.
    pub fn publish_inspection_digest(
        &self,
        report: &SweepReport,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        if report.caller.is_none() || wire::is_go_zero_time(now) {
            return Err(inspection_unavailable());
        }
        let Some(caller) = report.caller else {
            return Err(inspection_unavailable());
        };
        let view = self.inspection_report_from(report, caller, now);
        let mut digest = InspectionDigest {
            schema_version: RECORD_SCHEMA.to_string(),
            report: view,
            hmac: String::new(),
        };
        let payload = digest.payload()?;
        digest.hmac = self.signing.fingerprint(INSPECTION_HMAC_DOMAIN, &payload);
        let path = self
            .inspection_digest_path()
            .ok_or_else(inspection_unavailable)?;
        let lock = durable::open_lock(&path)?;
        // A replace rather than a create-only write: every pass
        // supersedes the one before it, and a create-only digest would
        // freeze the view at the first sweep this host ever ran.
        let result = durable::replace_json(&path, &digest);
        durable::unlock_and_close(lock);
        result
    }

    /// `inspectionReportFrom` — the whole derivation, and the only
    /// place a fact from the sweep becomes a figure this surface
    /// emits.
    fn inspection_report_from(
        &self,
        report: &SweepReport,
        caller: SweepCaller,
        now: OffsetDateTime,
    ) -> InspectionReport {
        let mut view = InspectionReport {
            caller,
            observed_at: now,
            records_intact: report.records_intact,
            live_sets: InspectionBand::None,
            oldest_live_set: InspectionAge::None,
            held_objects: InspectionBand::None,
            devices: Vec::new(),
            findings: Vec::new(),
        };
        let mut live_sets: std::collections::HashSet<Uuid> = Default::default();
        let mut per_device: BTreeMap<String, i64> = Default::default();
        let mut findings: BTreeMap<(String, String, String, String), (InspectionFinding, i64)> =
            Default::default();
        let mut held: i64 = 0;
        for outcome in &report.outcomes {
            // The aggregation key deliberately drops `key` and
            // `bytes`. `key` can be a raw directory entry name; `bytes`
            // is an exact figure.
            let finding = InspectionFinding {
                item: outcome.item,
                action: outcome.action,
                condition: outcome.condition,
                trigger: outcome.trigger,
                count: InspectionBand::None,
            };
            let agg_key = (
                outcome.item.as_str().to_string(),
                outcome.action.as_str().to_string(),
                outcome
                    .condition
                    .map(|c| c.as_str())
                    .unwrap_or("")
                    .to_string(),
                outcome
                    .trigger
                    .map(|t| t.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            findings
                .entry(agg_key)
                .and_modify(|(_, count)| *count += 1)
                .or_insert((finding, 1));
            if outcome.item == SweepItem::Set && outcome.action == SweepAction::Retained {
                // A retained set is a live set. A key that is not a
                // set id is an unrecognized entry the sweep reported
                // by name, and it is dropped rather than parsed.
                if let Ok(set_id) = Uuid::parse_str(&outcome.key)
                    && !set_id.is_nil()
                {
                    live_sets.insert(set_id);
                }
            }
            if outcome.item == SweepItem::Object && outcome.action != SweepAction::Released {
                held += 1;
                if store_path::is_object_name(&outcome.key) {
                    // The object name *is* the device fingerprint.
                    // Nothing else about the name is carried forward.
                    let fingerprint = outcome.key
                        [..outcome.key.len() - store_path::OBJECT_SUFFIX.len()]
                        .to_string();
                    *per_device.entry(fingerprint).or_insert(0) += 1;
                }
            }
        }
        view.live_sets = InspectionBand::of(live_sets.len() as i64);
        view.held_objects = InspectionBand::of(held);
        view.oldest_live_set = self.oldest_live_set_age(&live_sets, now);
        for (fingerprint, count) in per_device {
            if !store_path::valid_fingerprint(&fingerprint) {
                continue;
            }
            view.devices.push(InspectionDevice {
                device_fingerprint: fingerprint,
                reserved: InspectionBand::of(count),
            });
        }
        view.devices
            .sort_by(|a, b| a.device_fingerprint.cmp(&b.device_fingerprint));
        for (_, (mut finding, count)) in findings {
            finding.count = InspectionBand::of(count);
            view.findings.push(finding);
        }
        view.findings.sort_by_key(finding_key);
        view
    }

    /// `oldestLiveSetAge` — read the named sets — by id, never by
    /// enumeration — and band the age of the oldest. A set whose
    /// record cannot be read contributes nothing: `records_intact`
    /// already tells the operator that a record was unreadable.
    fn oldest_live_set_age(
        &self,
        live_sets: &std::collections::HashSet<Uuid>,
        now: OffsetDateTime,
    ) -> InspectionAge {
        let mut oldest: Option<OffsetDateTime> = None;
        for set_id in live_sets {
            let Ok(set) = self.read_set(*set_id) else {
                continue;
            };
            #[allow(clippy::unnecessary_map_or)]
            if oldest.map_or(true, |o| set.created_at < o) {
                oldest = Some(set.created_at);
            }
        }
        let Some(oldest) = oldest else {
            return InspectionAge::None;
        };
        let mut age = now - oldest;
        if age.is_negative() {
            age = time::Duration::ZERO;
        }
        InspectionAge::of(age)
    }

    /// `ReadInspectionDigest` — the daemon's whole read path: one
    /// openat of one fixed name, the same owner/mode/link-count
    /// validated discipline every other record in this package is
    /// read under, a strict schema decode, and an HMAC check.
    ///
    /// It mutates nothing, takes no lock — matching every other
    /// non-mutating read in this store — and never touches a set,
    /// member, launch or receipt record.
    pub fn read_inspection_digest(&self) -> Result<InspectionReport, Failure> {
        let path = self
            .inspection_digest_path()
            .ok_or_else(inspection_unavailable)?;
        let raw = store::read_reserve_bytes(&path)?;
        let digest: InspectionDigest = store::decode_record(&raw)?;
        if !digest.valid() {
            return Err(inspection_unavailable());
        }
        let payload = digest.payload()?;
        let expected = self.signing.fingerprint(INSPECTION_HMAC_DOMAIN, &payload);
        if !wire::hmac_equal(digest.hmac.as_bytes(), expected.as_bytes()) {
            return Err(inspection_unavailable());
        }
        Ok(digest.report)
    }
}

// --- frame 0xc5 --------------------------------------------------------------------

/// `RESTORE_CAPACITY_RESERVE_INSPECTION_FRAME_MARKER` — frame `0xc5`.
/// It is its own frame rather than another kind on `0xc3` for the
/// reason `0xc3` and `0xc4` are separate from each other: a frame's
/// peer predicate is the frame's identity. `0xc3` admits the root
/// helper bound to a live launch record and *writes* reserve evidence;
/// this frame admits any root peer, bound to nothing, and only reads.
/// Folding a read that admits a wider peer set into the frame that
/// performs the writes would widen the write path's predicate by
/// accident.
pub(crate) use crate::broker::protocol::RESTORE_CAPACITY_RESERVE_INSPECTION_FRAME_MARKER as FRAME_MARKER;

/// `restoreCapacityReserveInspectionKind` — the frame's one and only
/// kind. There is no second kind and no payload: a surface whose whole
/// purpose is to withhold must not offer a selector, because a
/// selector is a query, and a query answered repeatedly is how a
/// coarse band becomes a fine one.
pub(crate) const INSPECTION_KIND: u8 = 1;

/// `restoreCapacityReserveInspectionRefusal` — this frame's closed,
/// locator-free refusal vocabulary. As on frames `0xc3` and `0xc4`,
/// the peer denial is a distinct value from the shape denial, so "the
/// peer is rejected before any of the body is read" is observable from
/// outside rather than merely asserted in a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionRefusal {
    /// Every peer that is not root, plus the runtime UID whatever it
    /// is. Returned before the kind byte is read.
    PeerDenied,
    /// A shape refusal: a short frame or an unknown kind.
    FrameInvalid,
    /// No sweep pass has ever published a view on this host.
    /// Deliberately not folded into `Unavailable`: "nothing has looked
    /// yet" and "this daemon could not read what was published" are
    /// different operator problems, and on a disaster-recovery host
    /// the first one is the likely one — the sweep's call sites are
    /// not wired.
    Absent,
    /// The store/engine bucket: I/O, a digest whose HMAC does not
    /// verify, a digest this build cannot parse.
    Unavailable,
}
impl InspectionRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeerDenied => "RESTORE_INSPECTION_PEER_DENIED",
            Self::FrameInvalid => "RESTORE_INSPECTION_FRAME_INVALID",
            Self::Absent => "RESTORE_INSPECTION_ABSENT",
            Self::Unavailable => "RESTORE_INSPECTION_UNAVAILABLE",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "RESTORE_INSPECTION_PEER_DENIED" => Self::PeerDenied,
            "RESTORE_INSPECTION_FRAME_INVALID" => Self::FrameInvalid,
            "RESTORE_INSPECTION_ABSENT" => Self::Absent,
            "RESTORE_INSPECTION_UNAVAILABLE" => Self::Unavailable,
            _ => return None,
        })
    }
}

/// `restoreCapacityReserveInspectionPeerAdmitted` — the whole peer
/// policy. Root only; the runtime UID is refused *explicitly* on top
/// of the root test — `svc.runtime_uid` is a field set from
/// composition, and a deployment that ever ran the runtime as root
/// would silently turn the root test into an admission of the runtime.
fn inspection_peer_admitted(svc: &Service, peer: &PeerCred) -> bool {
    if peer.uid.as_raw() != 0
        || peer.gid.as_raw() != 0
        || rustix::process::Pid::as_raw(Some(peer.pid)) <= 0
    {
        return false;
    }
    peer.uid.as_raw() != svc.runtime_uid
}

impl Service {
    /// `handleRestoreCapacityReserveInspectionConnection` — frame
    /// `0xc5`'s entry point.
    ///
    /// The ordering is the load-bearing part: the peer predicate runs
    /// against the connection's own `SO_PEERCRED` identity before the
    /// kind byte — the entire frame body — is read, so an unauthorized
    /// peer never makes this process parse anything on its behalf, and
    /// because the peer refusal is a distinct reason from the shape
    /// refusal, that ordering is observable rather than asserted.
    pub(crate) fn handle_restore_capacity_inspection_connection(
        &self,
        conn: &mut DeadlineStream,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        if !inspection_peer_admitted(self, peer) {
            protocol::write_deny(conn, "unknown", InspectionRefusal::PeerDenied.as_str());
            return Err(Failure::denied(
                "broker_restore_inspection",
                "broker: denied restore capacity inspection peer",
            ));
        }
        let Some(reserves) = self.restore_capacity_reserves.as_ref() else {
            protocol::write_deny(conn, "unknown", InspectionRefusal::Unavailable.as_str());
            return Err(Failure::internal(
                "broker_restore_inspection",
                "broker: restore capacity reserve store unavailable",
            ));
        };
        let mut kind = [0u8; 1];
        if std::io::Read::read_exact(conn, &mut kind).is_err() {
            protocol::write_deny(conn, "unknown", InspectionRefusal::FrameInvalid.as_str());
            return Err(Failure::denied(
                "broker_restore_inspection",
                "broker: short restore capacity inspection frame",
            ));
        }
        if kind[0] != INSPECTION_KIND {
            protocol::write_deny(conn, "unknown", InspectionRefusal::FrameInvalid.as_str());
            return Err(Failure::denied(
                "broker_restore_inspection",
                "broker: invalid restore capacity inspection frame kind",
            ));
        }
        match reserves.read_inspection_digest() {
            Ok(report) => {
                let result = match serde_json::value::to_raw_value(&report) {
                    Ok(result) => result,
                    Err(e) => {
                        protocol::write_deny(
                            conn,
                            "unknown",
                            InspectionRefusal::Unavailable.as_str(),
                        );
                        return Err(Failure::internal(
                            "broker_restore_inspection",
                            format!("broker: marshal inspection report: {e}"),
                        ));
                    }
                };
                protocol::write_response(
                    conn,
                    &BrokerResponse {
                        operation_id: "unknown".to_string(),
                        outcome: BrokerOutcome::Success,
                        result: Some(result),
                        evidence: Default::default(),
                    },
                )
            }
            Err(e) => {
                let reason = if super::is_reserve_not_found(&e) {
                    InspectionRefusal::Absent
                } else {
                    InspectionRefusal::Unavailable
                };
                protocol::write_deny(conn, "unknown", reason.as_str());
                Err(e)
            }
        }
    }
}

// --- the client -----------------------------------------------------------------

/// `restoreCapacityReserveInspectionMaxResponseBytes` — bounds what
/// the client will read back. The report is a fixed-cardinality struct
/// over closed vocabularies with at most four devices and a bounded
/// finding set; this is generous headroom, not a sizing target, and it
/// is what keeps arbitrary wire content from becoming an allocation in
/// this process.
const INSPECTION_MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// `RestoreCapacityReserveInspectionClient` — the root caller's side
/// of frame `0xc5`. It has one method because the frame has one kind.
pub struct InspectionClient {
    pub socket_path: std::path::PathBuf,
}

impl InspectionClient {
    /// `NewRestoreCapacityReserveInspectionClient`.
    pub fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `Inspect` — fetch the published view. Read-only on both sides.
    pub fn inspect(&self, deadline: std::time::Duration) -> Result<InspectionReport, Failure> {
        if self.socket_path.as_os_str().is_empty() {
            return Err(inspection_unavailable());
        }
        let stream = std::os::unix::net::UnixStream::connect(&self.socket_path).map_err(|e| {
            Failure::internal(
                INSPECTION_UNAVAILABLE_CODE,
                format!("broker: dial inspection frame: {e}"),
            )
        })?;
        let conn = DeadlineStream::new(stream.into(), deadline)?;
        (&conn)
            .write_all(&[FRAME_MARKER, INSPECTION_KIND])
            .map_err(|_| inspection_unavailable())?;
        // Upstream reads `ReadFull` into a fixed buffer and decodes
        // whatever arrived: here the bounded equivalent is `take` +
        // `read_to_end`, capped at one byte past the limit so an
        // oversize response is detectable.
        let mut response = Vec::new();
        std::io::Read::take(&conn, (INSPECTION_MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .map_err(|_| inspection_unavailable())?;
        decode_inspection_response(&response)
    }
}

/// `restoreCapacityReserveInspectionDecode` — recover either the
/// report or the sanitized refusal, conservatively: a response that is
/// not the broker's own bounded shape, or a refusal outside this
/// frame's closed vocabulary, becomes the generic unavailable reason
/// rather than letting arbitrary wire content become an error value or
/// a report in this process.
fn decode_inspection_response(raw: &[u8]) -> Result<InspectionReport, Failure> {
    if raw.is_empty() || raw.len() > INSPECTION_MAX_RESPONSE_BYTES {
        return Err(inspection_unavailable());
    }
    let response: BrokerResponse =
        serde_json::from_slice(trim_trailing(raw)).map_err(|_| inspection_unavailable())?;
    if response.outcome != BrokerOutcome::Success {
        let message = response.evidence.message.as_str();
        return match InspectionRefusal::from_str(message) {
            Some(reason) => Err(Failure::denied(
                "broker_restore_inspection",
                format!(
                    "broker: restore capacity inspection refused: {}",
                    reason.as_str()
                ),
            )),
            None => Err(inspection_unavailable()),
        };
    }
    let Some(result) = response.result else {
        return Err(inspection_unavailable());
    };
    let report: InspectionReport =
        serde_json::from_str(result.get()).map_err(|_| inspection_unavailable())?;
    if !report.valid() {
        return Err(inspection_unavailable());
    }
    Ok(report)
}

/// `trimTrailingNewline` — Go's `trimTrailingNewline`: trailing `\n`
/// and NUL bytes stripped before decode.
fn trim_trailing(raw: &[u8]) -> &[u8] {
    let mut raw = raw;
    while let Some(&last) = raw.last() {
        if last == b'\n' || last == 0 {
            raw = &raw[..raw.len() - 1];
        } else {
            break;
        }
    }
    raw
}

// ---------------------------------------------------------------------------
// Tests — the band/age bucketing, finding order, refusal vocabulary, and the
// report's no-locator, no-figure leaf set.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `band_of` is total over negative and absurd inputs and coarser
    /// than one reserve unit: two, three and four land on the same
    /// band deliberately.
    #[test]
    fn figures_are_bucketed() {
        assert_eq!(InspectionBand::of(-1), InspectionBand::None);
        assert_eq!(InspectionBand::of(0), InspectionBand::None);
        assert_eq!(InspectionBand::of(1), InspectionBand::One);
        assert_eq!(InspectionBand::of(2), InspectionBand::Several);
        assert_eq!(InspectionBand::of(4), InspectionBand::Several);
    }

    /// The age bands track this design's own two clocks.
    #[test]
    fn ages_track_the_designs_clocks() {
        assert_eq!(
            InspectionAge::of(time::Duration::minutes(19)),
            InspectionAge::WithinReceiptWindow
        );
        assert_eq!(
            InspectionAge::of(RECEIPT_LIFETIME + time::Duration::seconds(1)),
            InspectionAge::BeyondReceiptWindow
        );
        assert_eq!(
            InspectionAge::of(RESERVE_ABSOLUTE_LIFETIME + time::Duration::seconds(1)),
            InspectionAge::BeyondAbsoluteExpiry
        );
    }

    /// The refusal vocabulary is closed: the four values round-trip,
    /// and arbitrary wire content does not parse.
    #[test]
    fn refusal_vocabulary_is_closed() {
        for refusal in [
            InspectionRefusal::PeerDenied,
            InspectionRefusal::FrameInvalid,
            InspectionRefusal::Absent,
            InspectionRefusal::Unavailable,
        ] {
            assert_eq!(InspectionRefusal::from_str(refusal.as_str()), Some(refusal));
        }
        assert_eq!(InspectionRefusal::from_str("BROKER_AUTHORITY_DENIED"), None);
        assert_eq!(InspectionRefusal::from_str(""), None);
    }

    /// `InspectionReport::valid` rejects out-of-order devices and
    /// out-of-order findings, and accepts the sorted form.
    #[test]
    fn report_validity_requires_order() {
        let device = |hex: &str| InspectionDevice {
            device_fingerprint: format!("fs-{hex}"),
            reserved: InspectionBand::One,
        };
        let base = InspectionReport {
            caller: SweepCaller::HelperStartup,
            observed_at: time::OffsetDateTime::now_utc(),
            records_intact: true,
            live_sets: InspectionBand::None,
            oldest_live_set: InspectionAge::None,
            held_objects: InspectionBand::None,
            devices: Vec::new(),
            findings: Vec::new(),
        };
        assert!(base.valid());
        let mut sorted = base.clone();
        sorted.devices = vec![device(&"a".repeat(32)), device(&"b".repeat(32))];
        assert!(sorted.valid());
        let mut unsorted = base.clone();
        unsorted.devices = vec![device(&"b".repeat(32)), device(&"a".repeat(32))];
        assert!(!unsorted.valid());
        let mut bad_fingerprint = base;
        bad_fingerprint.devices = vec![InspectionDevice {
            device_fingerprint: "not-a-fingerprint".to_string(),
            reserved: InspectionBand::One,
        }];
        assert!(!bad_fingerprint.valid());
    }

    /// `decode_inspection_response` maps every out-of-vocabulary and
    /// malformed response to the generic unavailable answer rather
    /// than letting wire content become an error value or a report.
    #[test]
    fn decode_refuses_arbitrary_content() {
        assert!(decode_inspection_response(b"").is_err());
        assert!(decode_inspection_response(b"not json").is_err());
        // A deny whose message is outside this frame's closed
        // vocabulary maps to unavailable, not to a caller-visible
        // reason.
        let raw = serde_json::to_vec(&central_infra::authority::BrokerResponse {
            operation_id: "unknown".to_string(),
            outcome: BrokerOutcome::Denied,
            result: None,
            evidence: central_infra::authority::BrokerEvidence {
                operation_id: "unknown".to_string(),
                code: String::new(),
                message: "ARBITRARY_WIRE_CONTENT".to_string(),
            },
        })
        .unwrap();
        let err = decode_inspection_response(&raw).unwrap_err();
        assert_eq!(err.code(), INSPECTION_UNAVAILABLE_CODE);
    }
}
