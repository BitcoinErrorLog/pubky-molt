//! S5. Witnesses, fields, domains, segments, detach levels.
//!
//! Two independent models, never merged: **what observers learn** ([`Field`],
//! [`Witness`], [`Manifest`]) and **what the protocol requires to stay
//! continuous** ([`CorrelatorSpec`], [`Segment`]). A third distinction runs
//! across both: a *spec* (a kind of identifier, used statically in manifests
//! and planning) versus a *correlator* (a specific value of that kind,
//! carried as a BLAKE3 fingerprint in execution traces and vectors).

use crate::{to_hex, validate_namespace, MoltError};
use bitflags::bitflags;
use ciborium::value::{Integer, Value};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

bitflags! {
    /// The observer vocabulary: what a [`Witness`] necessarily learns on one
    /// side of a hop, and the `kind` class of a [`CorrelatorSpec`].
    ///
    /// Field count is not privacy loss; a counterparty learning
    /// `RELATIONSHIP_IDENTITY | CONTEXT_ID | AMOUNT | TIME` is a bilateral
    /// protocol working as designed. What Molt removes is e.g. a relay
    /// learning `RELATIONSHIP_LINK`.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct Field: u32 {
        /// A Pubky root identity.
        const ROOT_IDENTITY          = 1 << 0;
        /// "Who my counterparty is" within a bond.
        const RELATIONSHIP_IDENTITY  = 1 << 1;
        /// A pair public / bond-derived key material.
        const PAIRWISE_KEY           = 1 << 2;
        /// UTXO/script, LN node/channel id, `.onion` address.
        const NETWORK_IDENTIFIER     = 1 << 3;
        /// Source endpoint of a hop.
        const SOURCE_ENDPOINT        = 1 << 4;
        /// Destination endpoint of a hop.
        const DEST_ENDPOINT          = 1 << 5;
        /// Txid, payment hash, swap hash.
        const TRANSACTION_ID         = 1 << 6;
        /// Invoice, credit obligation, service commitment, contract state,
        /// or other protocol-specific obligation id.
        const OBLIGATION_ID          = 1 << 7;
        /// Application context id.
        const CONTEXT_ID             = 1 << 8;
        /// "Same pair as another observed message" (a join, not a disclosure).
        const RELATIONSHIP_LINK      = 1 << 9;
        /// Asset class (e.g. BTC vs USD).
        const ASSET                  = 1 << 10;
        /// Denomination unit (e.g. sat vs cent).
        const DENOMINATION           = 1 << 11;
        /// Transferred value.
        const AMOUNT                 = 1 << 12;
        /// Observation time.
        const TIME                   = 1 << 13;
        /// Message/payment content.
        const CONTENT                = 1 << 14;
        /// Content size fingerprint.
        const CONTENT_SIZE           = 1 << 15;
        /// Network location (IP, ASN) of an observed party.
        const NETWORK_LOCATION       = 1 << 16;
        /// Noise session id, QUIC connection id, TCP 4-tuple.
        const SESSION_IDENTIFIER     = 1 << 17;
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl Serialize for Field {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let mut out = String::new();
            bitflags::parser::to_writer(self, &mut out).map_err(serde::ser::Error::custom)?;
            s.serialize_str(&out)
        } else {
            s.serialize_u32(self.bits())
        }
    }
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            if s.trim().is_empty() {
                return Ok(Field::empty());
            }
            bitflags::parser::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let bits = u32::deserialize(d)?;
            Field::from_bits(bits)
                .ok_or_else(|| serde::de::Error::custom(format!("unknown Field bits {bits:#x}")))
        }
    }
}

/// An identifier for the operator of a witness (free-form, self-declared).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OperatorId(pub String);

/// A real-world entity an operator belongs to (e.g. a company, a chain
/// observer class). Witnesses whose domains intersect are not independent.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObservationDomain(pub String);

/// A declared belief that `operator` belongs to `domain`, with provenance.
///
/// Claims are data, never inferred silently. `infra_provider`, when present,
/// names an additional domain the operator's infrastructure depends on and is
/// unioned into the operator's known domains (conservative: depending on a
/// shared provider is a potential collusion path).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainClaim {
    /// The operator the claim is about.
    pub operator: OperatorId,
    /// The domain the operator is claimed to belong to.
    pub domain: ObservationDomain,
    /// Optional legal jurisdiction.
    pub jurisdiction: Option<String>,
    /// Optional infrastructure provider domain (unioned in).
    pub infra_provider: Option<ObservationDomain>,
    /// Provenance of the claim (URL, attestation id, "self-declared", ...).
    pub source: String,
    /// Unix timestamp the claim was asserted at.
    pub asserted_at: u64,
}

/// ADVISORY FOREVER. A bag of [`DomainClaim`]s with provenance, never
/// authoritative. Absence of a claim means independence is UNKNOWN, not
/// established. Adapters may state domains inline; users/apps may add
/// beliefs; a registry may supply optional knowledge. No component may treat
/// the registry as a global "who owns whom" oracle.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRegistry {
    claims: Vec<DomainClaim>,
}

impl DomainRegistry {
    /// An empty registry (the v1 default: nothing is known).
    pub fn new() -> Self {
        DomainRegistry { claims: Vec::new() }
    }

    /// Add a claim. Duplicate claims are kept; provenance is additive.
    pub fn add_claim(&mut self, claim: DomainClaim) {
        self.claims.push(claim);
    }

    /// All claims about `operator`.
    pub fn claims_for(&self, operator: &OperatorId) -> Vec<&DomainClaim> {
        self.claims
            .iter()
            .filter(|c| &c.operator == operator)
            .collect()
    }

    /// Known domains for `operator`: claimed domains plus claimed
    /// infrastructure providers.
    pub fn domains_for(&self, operator: &OperatorId) -> Vec<ObservationDomain> {
        let mut out: BTreeSet<ObservationDomain> = BTreeSet::new();
        for c in self.claims_for(operator) {
            out.insert(c.domain.clone());
            if let Some(p) = &c.infra_provider {
                out.insert(p.clone());
            }
        }
        out.into_iter().collect()
    }
}

/// The result of asking whether two witness sets belong to independent
/// observation domains.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Independence {
    /// Both sides have known domains and they are disjoint.
    Independent,
    /// The sides share at least one domain (listed).
    Shared(Vec<ObservationDomain>),
    /// At least one side has no known domain; independence is not established.
    Unknown,
}

/// The known domains of one witness: inline declarations unioned with
/// registry claims for its operator. Either source may add a domain; neither
/// may remove one.
fn witness_domains(w: &Witness, reg: &DomainRegistry) -> BTreeSet<ObservationDomain> {
    let mut out: BTreeSet<ObservationDomain> = w.domains.iter().cloned().collect();
    out.extend(reg.domains_for(&w.operator));
    out
}

/// Ask whether two sets of witnesses belong to independent observation
/// domains, using inline declarations unioned with registry claims.
pub fn independence(a: &[Witness], b: &[Witness], reg: &DomainRegistry) -> Independence {
    let da: BTreeSet<ObservationDomain> = a.iter().flat_map(|w| witness_domains(w, reg)).collect();
    let db: BTreeSet<ObservationDomain> = b.iter().flat_map(|w| witness_domains(w, reg)).collect();
    if da.is_empty() || db.is_empty() {
        return Independence::Unknown;
    }
    let shared: Vec<ObservationDomain> = da.intersection(&db).cloned().collect();
    if shared.is_empty() {
        Independence::Independent
    } else {
        Independence::Shared(shared)
    }
}

/// The role a witness plays in a protocol. Roles are descriptive; joins are
/// computed from domains, not roles.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WitnessRole {
    /// A Pubky homeserver operator.
    Homeserver,
    /// A Drop/relay operator.
    RelayOperator,
    /// A mainline DHT node.
    DhtNode,
    /// A Lightning peer.
    LnPeer,
    /// A blockchain observer (chain analysis).
    Chain,
    /// An internet service provider.
    Isp,
    /// A VPN operator.
    Vpn,
    /// A Tor guard relay.
    TorGuard,
    /// A Tor exit relay.
    TorExit,
    /// A Tor hidden-service directory.
    HsDir,
    /// A coordination party (e.g. a CoinJoin coordinator).
    Coordinator,
    /// An exchange.
    Exchange,
    /// A market/platform operator.
    Platform,
    /// The protocol counterparty.
    Counterparty,
    /// An intermediary (e.g. in a bounded transfer).
    Intermediary,
    /// Any other role, named by the adapter.
    Other(String),
}

/// A party that necessarily observes part of an interaction.
///
/// `domains` declared inline by the adapter are unioned with registry claims
/// for `operator`. `learns_in` / `learns_out` are the [`Field`]s the witness
/// necessarily observes on the input / output side of the hop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness {
    /// What this witness is.
    pub role: WitnessRole,
    /// Who operates it.
    pub operator: OperatorId,
    /// Inline-declared observation domains (unioned with registry claims).
    pub domains: Vec<ObservationDomain>,
    /// Fields observed on the input side of the hop.
    pub learns_in: Field,
    /// Fields observed on the output side of the hop.
    pub learns_out: Field,
}

/// A KIND of matchable identifier. `kind` is the observer-vocabulary class;
/// `namespace` is the protocol-vocabulary name with a [`crate::PurposeId`]-like
/// grammar (e.g. `"lightning.payment_hash"`, `"bitcoin.txid"`,
/// `"credit.receipt_id"`, `"btc.sats"`, `"time.unix"`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CorrelatorSpec {
    /// The observer-vocabulary class.
    pub kind: Field,
    /// The protocol-vocabulary name.
    pub namespace: String,
}

impl CorrelatorSpec {
    /// Construct a spec, validating the namespace grammar.
    pub fn new(kind: Field, namespace: &str) -> Result<Self, MoltError> {
        validate_namespace(namespace)?;
        Ok(CorrelatorSpec {
            kind,
            namespace: namespace.to_string(),
        })
    }

    /// Deterministic CBOR (RFC 8949 §4.2), integer map keys:
    /// `{0: kind_bits, 1: namespace}`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, MoltError> {
        let v = Value::Map(vec![
            (
                Value::Integer(Integer::from(0u8)),
                Value::Integer(Integer::from(self.kind.bits())),
            ),
            (
                Value::Integer(Integer::from(1u8)),
                Value::Text(self.namespace.clone()),
            ),
        ]);
        to_canonical_cbor(&v)
    }
}

/// Serialize a [`Value`] as deterministic CBOR: integer keys are emitted in
/// ascending order, integers in shortest form (ciborium's default), definite
/// lengths throughout.
fn to_canonical_cbor(v: &Value) -> Result<Vec<u8>, MoltError> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|e| MoltError::Cbor(e.to_string()))?;
    Ok(out)
}

/// A SPECIFIC value of a [`CorrelatorSpec`] kind, carried only as a BLAKE3
/// fingerprint. Never carries the raw value.
///
/// `fingerprint = BLAKE3("pubky-molt/fp/v1" || namespace || canonical_value)[0..32]`.
/// For `AMOUNT`/`TIME` the canonical value is the exact figure, so equality
/// is an exact match and nearness must be judged by the scorer's window
/// logic, not by fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Correlator {
    /// The kind of identifier this is a value of.
    pub spec: CorrelatorSpec,
    /// BLAKE3 fingerprint of the canonical value (hex in JSON).
    pub fingerprint: [u8; 32],
}

impl Correlator {
    /// Domain-separation prefix for correlator fingerprints.
    pub const FINGERPRINT_PREFIX: &'static [u8] = b"pubky-molt/fp/v1";

    /// Fingerprint a canonical value under a spec.
    pub fn new(spec: CorrelatorSpec, canonical_value: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(Self::FINGERPRINT_PREFIX);
        h.update(spec.namespace.as_bytes());
        h.update(canonical_value);
        Correlator {
            spec,
            fingerprint: *h.finalize().as_bytes(),
        }
    }

    /// Deterministic CBOR (RFC 8949 §4.2), integer map keys:
    /// `{0: spec, 1: fingerprint_bytes}`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, MoltError> {
        let spec = ciborium::Value::serialized(&SpecCbor(self.spec.clone()))
            .map_err(|e: ciborium::value::Error| MoltError::Cbor(e.to_string()))?;
        let v = Value::Map(vec![
            (Value::Integer(Integer::from(0u8)), spec),
            (
                Value::Integer(Integer::from(1u8)),
                Value::Bytes(self.fingerprint.to_vec()),
            ),
        ]);
        to_canonical_cbor(&v)
    }
}

/// Helper: CBOR form of a spec (integer keys), reused by [`Correlator::to_cbor`]
/// and [`Segment::to_cbor`].
struct SpecCbor(CorrelatorSpec);

impl Serialize for SpecCbor {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(2))?;
        m.serialize_entry(&0u8, &self.0.kind.bits())?;
        m.serialize_entry(&1u8, &self.0.namespace)?;
        m.end()
    }
}

impl Serialize for Correlator {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            use serde::ser::SerializeStruct;
            let mut st = s.serialize_struct("Correlator", 2)?;
            st.serialize_field("spec", &self.spec)?;
            st.serialize_field("fingerprint", &to_hex(&self.fingerprint))?;
            st.end()
        } else {
            use serde::ser::SerializeStruct;
            let mut st = s.serialize_struct("Correlator", 2)?;
            st.serialize_field("spec", &self.spec)?;
            st.serialize_field("fingerprint", &self.fingerprint.as_slice())?;
            st.end()
        }
    }
}

impl<'de> Deserialize<'de> for Correlator {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Rep {
            spec: CorrelatorSpec,
            fingerprint: String,
        }
        let rep = Rep::deserialize(d)?;
        let bytes = crate::from_hex(&rep.fingerprint).map_err(serde::de::Error::custom)?;
        let fingerprint: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("fingerprint must be 32 bytes, got {}", v.len()))
        })?;
        Ok(Correlator {
            spec: rep.spec,
            fingerprint,
        })
    }
}

/// Execution-time record: which correlators actually crossed which boundary.
/// Produced by executors, consumed by traces and vectors to confirm or refute
/// joins predicted by the static scorer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTrace {
    /// `(boundary_index, correlators)` pairs, one entry per observed boundary.
    pub crossings: Vec<(usize, Vec<Correlator>)>,
}

/// The verdict of checking a predicted join against an execution trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceVerdict {
    /// Equal fingerprints at both boundaries: the predicted join is real.
    Confirmed,
    /// The spec was observed at both boundaries with different fingerprints:
    /// the predicted join is refuted.
    Refuted,
    /// The spec was not observed at both boundaries; the trace says nothing.
    InsufficientData,
}

impl RouteTrace {
    /// Correlators recorded at `boundary`, if any.
    pub fn correlators_at(&self, boundary: usize) -> Option<&[Correlator]> {
        self.crossings
            .iter()
            .find(|(b, _)| *b == boundary)
            .map(|(_, c)| c.as_slice())
    }

    /// Check a predicted join via `spec` between boundaries `i` and `j` by
    /// fingerprint equality.
    pub fn check_predicted_join(&self, i: usize, j: usize, spec: &CorrelatorSpec) -> TraceVerdict {
        let find = |b: usize| -> Option<&Correlator> {
            self.correlators_at(b)
                .and_then(|cs| cs.iter().find(|c| &c.spec == spec))
        };
        match (find(i), find(j)) {
            (Some(a), Some(b)) => {
                if a.fingerprint == b.fingerprint {
                    TraceVerdict::Confirmed
                } else {
                    TraceVerdict::Refuted
                }
            }
            _ => TraceVerdict::InsufficientData,
        }
    }
}

/// An adapter's declared disclosure: which [`Witness`] learns which [`Field`]s
/// on each side of the hop, and which correlator kinds cross the hop
/// untransformed.
///
/// `preserves` names the KINDS of correlator whose value crosses this hop
/// untransformed (e.g. spec `{AMOUNT, "btc.sats"}`, spec
/// `{TRANSACTION_ID, "lightning.payment_hash"}`). Planning is static: a
/// preserved spec means, by construction, that the same value crosses.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Id of the adapter this manifest belongs to.
    pub adapter_id: String,
    /// Parties that necessarily observe this hop.
    pub witnesses: Vec<Witness>,
    /// Correlator kinds whose value crosses this hop untransformed.
    pub preserves: Vec<CorrelatorSpec>,
    /// Upper bound on hop latency, if the adapter declares one.
    pub latency_bound_secs: Option<u32>,
}

/// The identifier of a [`Segment`] (adapter-scoped, must be unique per route).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SegmentId(pub String);

/// A span of a route over which an adapter declares correlator KINDS must
/// stay continuous (the same value crosses). Protocol-neutral: a Lightning
/// HTLC path `{TRANSACTION_ID, "lightning.payment_hash"}`, a swap lock→claim
/// `{TRANSACTION_ID, "swap.hash"}`, a Noise live session
/// `{SESSION_IDENTIFIER, "noise.session_id"}`, a bounded transfer through one
/// intermediary `{OBLIGATION_ID, "credit.receipt_id"}`.
///
/// Inside a segment: checked as preserved, never scored. Past the closing
/// hop: must stop; crossing past a close is a scored leak.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    /// Unique (per route) segment id.
    pub id: SegmentId,
    /// Correlator kinds carried continuously across the segment.
    pub carries: Vec<CorrelatorSpec>,
}

impl Segment {
    /// Deterministic CBOR (RFC 8949 §4.2), integer map keys:
    /// `{0: id, 1: carries}`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, MoltError> {
        let carries: Result<Vec<Value>, MoltError> = self
            .carries
            .iter()
            .map(|c| {
                ciborium::Value::serialized(&SpecCbor(c.clone()))
                    .map_err(|e: ciborium::value::Error| MoltError::Cbor(e.to_string()))
            })
            .collect();
        let v = Value::Map(vec![
            (
                Value::Integer(Integer::from(0u8)),
                Value::Text(self.id.0.clone()),
            ),
            (Value::Integer(Integer::from(1u8)), Value::Array(carries?)),
        ]);
        to_canonical_cbor(&v)
    }
}

/// How a hop changes the set of open segments. An adapter may open, continue,
/// and close several segments in one hop (a Lightning path opens and closes
/// its payment-hash segment in a single adapter; a swap may close a chain
/// segment while opening a Lightning one).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentEffects {
    /// Segments this hop opens.
    pub opens: Vec<Segment>,
    /// Segments (already open) this hop continues.
    pub continues: Vec<SegmentId>,
    /// Segments (already open) this hop closes.
    pub closes: Vec<SegmentId>,
}

/// The assumption set a detach/scoring computation is made under. Recorded
/// alongside every result; there are no silent defaults in reported output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assumptions {
    /// Largest colluding set of domains considered.
    pub colluding_set_size: u8,
    /// Which [`Field`] kinds count as join-capable.
    pub join_kinds: Field,
    /// `AMOUNT`/`TIME` observations count as joins only within this window.
    pub time_window_secs: u32,
    /// Treat witnesses with no known domain as independent. Defaults to
    /// `false`: absence of a claim means independence is UNKNOWN.
    pub treat_unknown_as_independent: bool,
}

impl Default for Assumptions {
    fn default() -> Self {
        Assumptions {
            colluding_set_size: 1,
            join_kinds: Field::all(),
            time_window_secs: 3600,
            treat_unknown_as_independent: false,
        }
    }
}

impl Assumptions {
    /// Deterministic CBOR (RFC 8949 §4.2), integer map keys:
    /// `{0: colluding_set_size, 1: join_kinds_bits, 2: time_window_secs, 3: treat_unknown_as_independent}`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, MoltError> {
        let v = Value::Map(vec![
            (
                Value::Integer(Integer::from(0u8)),
                Value::Integer(Integer::from(self.colluding_set_size)),
            ),
            (
                Value::Integer(Integer::from(1u8)),
                Value::Integer(Integer::from(self.join_kinds.bits())),
            ),
            (
                Value::Integer(Integer::from(2u8)),
                Value::Integer(Integer::from(self.time_window_secs)),
            ),
            (
                Value::Integer(Integer::from(3u8)),
                Value::Bool(self.treat_unknown_as_independent),
            ),
        ]);
        to_canonical_cbor(&v)
    }
}

/// How detached a boundary is, under a named [`Assumptions`] set.
///
/// Plain-English caveat: none of these levels claims resistance to a global
/// passive observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetachLevel {
    /// A join-capable correlator crosses, or a domain is known to see one on
    /// both sides.
    None,
    /// No leak was found, but independence is not established for some
    /// witness pair (absence of a claim is not independence).
    Unknown,
    /// No leak, and every cross-boundary witness pair is independent.
    Independent,
    /// Independent, and it holds for every colluding subset of known domains
    /// of size ≤ k.
    CollusionBounded(u8),
}

/// A segment whose carried correlator kinds are not preserved across a
/// boundary they span. Structural protocol violation: the value the segment
/// requires to stay continuous does not cross.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentViolation {
    /// The segment whose continuity was broken.
    pub segment: SegmentId,
    /// Carried specs missing from the preceding hop's `preserves`.
    pub missing: Vec<CorrelatorSpec>,
}

impl fmt::Display for SegmentViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "segment {} missing preserves:", self.segment.0)?;
        for m in &self.missing {
            write!(f, " {{{:?},{}}}", m.kind, m.namespace)?;
        }
        Ok(())
    }
}

impl std::error::Error for SegmentViolation {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    In,
    Out,
}

/// Map of domain → fields observed by that domain on one side of a manifest.
/// Witnesses with no known domain contribute nothing here (their uncertainty
/// is handled by the `Unknown` arm of [`detach_level`]).
fn side_domain_kinds(
    m: &Manifest,
    side: Side,
    reg: &DomainRegistry,
) -> BTreeMap<ObservationDomain, Field> {
    let mut out: BTreeMap<ObservationDomain, Field> = BTreeMap::new();
    for w in &m.witnesses {
        let kinds = match side {
            Side::In => w.learns_in,
            Side::Out => w.learns_out,
        };
        for d in witness_domains(w, reg) {
            out.entry(d).and_modify(|k| *k |= kinds).or_insert(kinds);
        }
    }
    out
}

/// Does this leak spec count as join-capable under `asm`?
///
/// `AMOUNT`/`TIME` count only within `asm.time_window_secs`; a missing
/// latency bound is conservatively treated as within the window.
fn counts_as_leak(
    spec: &CorrelatorSpec,
    latency_bound_secs: Option<u32>,
    asm: &Assumptions,
) -> bool {
    if !spec.kind.intersects(asm.join_kinds) {
        return false;
    }
    let windowed = Field::AMOUNT | Field::TIME;
    if windowed.contains(spec.kind) {
        match latency_bound_secs {
            Some(l) => l <= asm.time_window_secs,
            None => true,
        }
    } else {
        true
    }
}

/// Is `spec` excluded from leaks because an open segment carries its kind?
fn excluded_by_open(spec: &CorrelatorSpec, open: &[Segment]) -> bool {
    open.iter().flat_map(|s| s.carries.iter()).any(|c| {
        c.kind.contains(spec.kind) && (spec.namespace.is_empty() || c.namespace == spec.namespace)
    })
}

/// All `k`-element subsets of `0..n`, as index vectors (deterministic order).
fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    fn rec(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..n {
            cur.push(i);
            rec(i + 1, n, k, cur, out);
            cur.pop();
        }
    }
    let mut out = Vec::new();
    if k <= n {
        rec(0, n, k, &mut Vec::new(), &mut out);
    }
    out
}

/// Compute the detach level of the boundary between hops `a` and `b`, given
/// the segments open across that boundary (opened at or before `a`, not
/// closed by `a`).
///
/// - For each open segment, every carried [`CorrelatorSpec`] MUST be in
///   `a.preserves`, else [`SegmentViolation`].
/// - `leaks = (a.preserves ∪ specs visible to some domain on both sides) ∖ ⋃ open.carries`.
/// - [`DetachLevel::None`]: leaks non-empty, or a domain is known (inline ∪
///   registry) to see a join-capable correlator on both sides.
/// - [`DetachLevel::Unknown`]: leaks empty, but [`independence`] is `Unknown`
///   for some cross-boundary witness pair and
///   `!asm.treat_unknown_as_independent`.
/// - [`DetachLevel::Independent`]: leaks empty (`AMOUNT`/`TIME` count only
///   within `asm.time_window_secs`) and every cross-boundary witness pair is
///   independent.
/// - `DetachLevel::CollusionBounded(k)`: Independent, and holds for every
///   colluding subset of known domains of size ≤ k.
pub fn detach_level(
    a: &Manifest,
    b: &Manifest,
    open: &[Segment],
    reg: &DomainRegistry,
    asm: &Assumptions,
) -> Result<DetachLevel, SegmentViolation> {
    detach_level_scoped(a, b, open, open, reg, asm)
}

/// [`detach_level`] with separate segment sets: the carries of every
/// `checked` segment MUST be in `a.preserves` (else [`SegmentViolation`]),
/// while the carries of every `excluded` segment are removed from the leak
/// set. The public entry point uses one set for both (a segment open across
/// a boundary is both checked and excluded). The scorer uses the split form
/// for a hop's own in→out crossing: the hop's *own opens* exclude their
/// carried specs (the adapter declares that continuity by opening the
/// segment; it is not required to repeat it in `preserves`) but are not
/// structural-checked, while segments passing through the hop are both.
pub(crate) fn detach_level_scoped(
    a: &Manifest,
    b: &Manifest,
    checked: &[Segment],
    excluded: &[Segment],
    reg: &DomainRegistry,
    asm: &Assumptions,
) -> Result<DetachLevel, SegmentViolation> {
    // 1. Structural check: checked segments must have their carries preserved.
    for seg in checked {
        let missing: Vec<CorrelatorSpec> = seg
            .carries
            .iter()
            .filter(|c| !a.preserves.contains(c))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(SegmentViolation {
                segment: seg.id.clone(),
                missing,
            });
        }
    }

    // 2. Leaks: a.preserves, plus kinds some domain sees on both sides,
    //    minus everything inside excluded segments.
    let mut leaks: Vec<CorrelatorSpec> = a
        .preserves
        .iter()
        .filter(|p| !excluded_by_open(p, excluded))
        .cloned()
        .collect();

    let da = side_domain_kinds(a, Side::Out, reg);
    let db = side_domain_kinds(b, Side::In, reg);
    for (dom, ka) in &da {
        if let Some(kb) = db.get(dom) {
            let common = *ka & *kb;
            for f in common.iter() {
                let spec = CorrelatorSpec {
                    kind: f,
                    namespace: String::new(),
                };
                if !excluded_by_open(&spec, excluded)
                    && counts_as_leak(&spec, a.latency_bound_secs, asm)
                {
                    leaks.push(spec);
                }
            }
        }
    }

    if leaks
        .iter()
        .any(|l| counts_as_leak(l, a.latency_bound_secs, asm))
    {
        return Ok(DetachLevel::None);
    }

    // 3. Unknown independence for any cross-boundary witness pair.
    if !asm.treat_unknown_as_independent {
        for wa in &a.witnesses {
            for wb in &b.witnesses {
                let da = witness_domains(wa, reg);
                let db = witness_domains(wb, reg);
                if da.is_empty() || db.is_empty() {
                    return Ok(DetachLevel::Unknown);
                }
            }
        }
    }

    // 4. Collusion analysis over known domains.
    let mut domains: Vec<ObservationDomain> = da.keys().chain(db.keys()).cloned().collect();
    domains.sort();
    domains.dedup();
    let max_k = (asm.colluding_set_size as usize).min(domains.len());
    let mut best = 1usize; // size 1 holds: leaks are empty
    for k in 2..=max_k {
        let mut holds = true;
        'subsets: for subset in combinations(domains.len(), k) {
            let mut ka = Field::empty();
            let mut kb = Field::empty();
            for &i in &subset {
                if let Some(f) = da.get(&domains[i]) {
                    ka |= *f;
                }
                if let Some(f) = db.get(&domains[i]) {
                    kb |= *f;
                }
            }
            let common = ka & kb;
            for f in common.iter() {
                let spec = CorrelatorSpec {
                    kind: f,
                    namespace: String::new(),
                };
                if !excluded_by_open(&spec, excluded)
                    && counts_as_leak(&spec, a.latency_bound_secs, asm)
                {
                    holds = false;
                    break 'subsets;
                }
            }
        }
        if holds {
            best = k;
        } else {
            break;
        }
    }
    if best >= 2 {
        Ok(DetachLevel::CollusionBounded(best as u8))
    } else {
        Ok(DetachLevel::Independent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: Field, ns: &str) -> CorrelatorSpec {
        CorrelatorSpec::new(kind, ns).expect("valid namespace")
    }

    fn witness(role: WitnessRole, op: &str, domains: &[&str], lin: Field, lout: Field) -> Witness {
        Witness {
            role,
            operator: OperatorId(op.into()),
            domains: domains
                .iter()
                .map(|d| ObservationDomain((*d).into()))
                .collect(),
            learns_in: lin,
            learns_out: lout,
        }
    }

    fn manifest(id: &str, witnesses: Vec<Witness>, preserves: Vec<CorrelatorSpec>) -> Manifest {
        Manifest {
            adapter_id: id.into(),
            witnesses,
            preserves,
            latency_bound_secs: Some(60),
        }
    }

    #[test]
    fn field_bit_values_match_spec() {
        assert_eq!(Field::ROOT_IDENTITY.bits(), 1 << 0);
        assert_eq!(Field::RELATIONSHIP_IDENTITY.bits(), 1 << 1);
        assert_eq!(Field::PAIRWISE_KEY.bits(), 1 << 2);
        assert_eq!(Field::NETWORK_IDENTIFIER.bits(), 1 << 3);
        assert_eq!(Field::SOURCE_ENDPOINT.bits(), 1 << 4);
        assert_eq!(Field::DEST_ENDPOINT.bits(), 1 << 5);
        assert_eq!(Field::TRANSACTION_ID.bits(), 1 << 6);
        assert_eq!(Field::OBLIGATION_ID.bits(), 1 << 7);
        assert_eq!(Field::CONTEXT_ID.bits(), 1 << 8);
        assert_eq!(Field::RELATIONSHIP_LINK.bits(), 1 << 9);
        assert_eq!(Field::ASSET.bits(), 1 << 10);
        assert_eq!(Field::DENOMINATION.bits(), 1 << 11);
        assert_eq!(Field::AMOUNT.bits(), 1 << 12);
        assert_eq!(Field::TIME.bits(), 1 << 13);
        assert_eq!(Field::CONTENT.bits(), 1 << 14);
        assert_eq!(Field::CONTENT_SIZE.bits(), 1 << 15);
        assert_eq!(Field::NETWORK_LOCATION.bits(), 1 << 16);
        assert_eq!(Field::SESSION_IDENTIFIER.bits(), 1 << 17);
    }

    #[test]
    fn field_serde_text_roundtrip_and_rejection() {
        let f = Field::ROOT_IDENTITY | Field::AMOUNT;
        let j = serde_json::to_string(&f).expect("ser");
        assert_eq!(j, "\"ROOT_IDENTITY | AMOUNT\"");
        let back: Field = serde_json::from_str(&j).expect("de");
        assert_eq!(back, f);
        assert!(serde_json::from_str::<Field>("\"NOT_A_FIELD\"").is_err());
    }

    #[test]
    fn independence_levels() {
        let reg = DomainRegistry::new();
        let a = vec![witness(
            WitnessRole::RelayOperator,
            "r1",
            &["relay-co"],
            Field::TIME,
            Field::TIME,
        )];
        let b = vec![witness(
            WitnessRole::Chain,
            "c1",
            &["chain-obs"],
            Field::AMOUNT,
            Field::AMOUNT,
        )];
        assert_eq!(independence(&a, &b, &reg), Independence::Independent);

        let b2 = vec![witness(
            WitnessRole::Chain,
            "c1",
            &["relay-co"],
            Field::AMOUNT,
            Field::AMOUNT,
        )];
        match independence(&a, &b2, &reg) {
            Independence::Shared(s) => assert_eq!(s, vec![ObservationDomain("relay-co".into())]),
            other => panic!("expected Shared, got {other:?}"),
        }

        let c = vec![witness(
            WitnessRole::Other("mystery".into()),
            "anon",
            &[],
            Field::TIME,
            Field::TIME,
        )];
        assert_eq!(independence(&a, &c, &reg), Independence::Unknown);
    }

    #[test]
    fn independence_unions_registry_claims_and_infra() {
        let mut reg = DomainRegistry::new();
        reg.add_claim(DomainClaim {
            operator: OperatorId("r1".into()),
            domain: ObservationDomain("big-cdn".into()),
            jurisdiction: None,
            infra_provider: Some(ObservationDomain("cloud-x".into())),
            source: "https://example.test/claim".into(),
            asserted_at: 1_700_000_000,
        });
        let a = vec![witness(
            WitnessRole::RelayOperator,
            "r1",
            &[],
            Field::TIME,
            Field::TIME,
        )];
        let b = vec![witness(
            WitnessRole::Isp,
            "isp1",
            &["cloud-x"],
            Field::TIME,
            Field::TIME,
        )];
        match independence(&a, &b, &reg) {
            Independence::Shared(s) => assert!(s.contains(&ObservationDomain("cloud-x".into()))),
            other => panic!("expected Shared via infra_provider, got {other:?}"),
        }
        assert_eq!(reg.claims_for(&OperatorId("nobody".into())).len(), 0);
    }

    #[test]
    fn detach_independent_when_no_leaks_and_domains_disjoint() {
        let reg = DomainRegistry::new();
        let a = manifest(
            "x",
            vec![witness(
                WitnessRole::RelayOperator,
                "r1",
                &["d1"],
                Field::CONTENT_SIZE,
                Field::CONTENT_SIZE,
            )],
            vec![],
        );
        let b = manifest(
            "y",
            vec![witness(
                WitnessRole::Homeserver,
                "h1",
                &["d2"],
                Field::CONTENT_SIZE,
                Field::CONTENT_SIZE,
            )],
            vec![],
        );
        // CONTENT_SIZE is not seen on both sides by the same domain, nothing preserved.
        let a2 = manifest(
            "x",
            vec![witness(
                WitnessRole::RelayOperator,
                "r1",
                &["d1"],
                Field::CONTENT_SIZE,
                Field::empty(),
            )],
            vec![],
        );
        let level =
            detach_level(&a2, &b, &[], &reg, &Assumptions::default()).expect("no violation");
        assert_eq!(level, DetachLevel::Independent);
        let _ = a;
    }

    #[test]
    fn detach_none_when_spec_leaks_past_close() {
        let reg = DomainRegistry::new();
        // The payment hash crosses a boundary with no open segment covering it:
        // a spec leaking past a closing hop.
        let a = manifest(
            "ln-out",
            vec![witness(
                WitnessRole::LnPeer,
                "ln1",
                &["ln-net"],
                Field::TRANSACTION_ID,
                Field::TRANSACTION_ID,
            )],
            vec![spec(Field::TRANSACTION_ID, "lightning.payment_hash")],
        );
        let b = manifest(
            "next",
            vec![witness(
                WitnessRole::Chain,
                "c1",
                &["chain"],
                Field::TIME,
                Field::TIME,
            )],
            vec![],
        );
        let level = detach_level(&a, &b, &[], &reg, &Assumptions::default()).expect("no violation");
        assert_eq!(level, DetachLevel::None);
    }

    #[test]
    fn detach_unknown_from_unregistered_witnesses() {
        let reg = DomainRegistry::new();
        let a = manifest(
            "x",
            vec![witness(
                WitnessRole::Other("opq".into()),
                "anon1",
                &[],
                Field::CONTENT_SIZE,
                Field::empty(),
            )],
            vec![],
        );
        let b = manifest(
            "y",
            vec![witness(
                WitnessRole::Other("opq".into()),
                "anon2",
                &[],
                Field::CONTENT_SIZE,
                Field::empty(),
            )],
            vec![],
        );
        let asm = Assumptions::default();
        assert_eq!(
            detach_level(&a, &b, &[], &reg, &asm).expect("ok"),
            DetachLevel::Unknown
        );
        let asm2 = Assumptions {
            treat_unknown_as_independent: true,
            ..asm
        };
        assert_eq!(
            detach_level(&a, &b, &[], &reg, &asm2).expect("ok"),
            DetachLevel::Independent
        );
    }

    #[test]
    fn detach_violation_when_open_segment_not_preserved() {
        let reg = DomainRegistry::new();
        let a = manifest("x", vec![], vec![spec(Field::AMOUNT, "btc.sats")]);
        let b = manifest("y", vec![], vec![]);
        let open = vec![Segment {
            id: SegmentId("ln".into()),
            carries: vec![spec(Field::TRANSACTION_ID, "lightning.payment_hash")],
        }];
        let err =
            detach_level(&a, &b, &open, &reg, &Assumptions::default()).expect_err("violation");
        assert_eq!(err.segment, SegmentId("ln".into()));
        assert_eq!(
            err.missing,
            vec![spec(Field::TRANSACTION_ID, "lightning.payment_hash")]
        );
    }

    #[test]
    fn open_segment_excludes_carried_spec_from_leaks() {
        let reg = DomainRegistry::new();
        let ph = spec(Field::TRANSACTION_ID, "lightning.payment_hash");
        let a = manifest("ln-a", vec![], vec![ph.clone()]);
        let b = manifest("ln-b", vec![], vec![ph.clone()]);
        let open = vec![Segment {
            id: SegmentId("ln".into()),
            carries: vec![ph],
        }];
        let level = detach_level(&a, &b, &open, &reg, &Assumptions::default()).expect("ok");
        assert_eq!(level, DetachLevel::Independent);
    }

    #[test]
    fn detach_none_when_domain_sees_join_kind_on_both_sides() {
        let reg = DomainRegistry::new();
        let a = manifest(
            "in",
            vec![witness(
                WitnessRole::Vpn,
                "vpn1",
                &["vpn-co"],
                Field::ROOT_IDENTITY,
                Field::DEST_ENDPOINT,
            )],
            vec![],
        );
        // vpn-co sees DEST_ENDPOINT out of a and DEST_ENDPOINT into b.
        let b2 = manifest(
            "out",
            vec![witness(
                WitnessRole::Vpn,
                "vpn1",
                &["vpn-co"],
                Field::DEST_ENDPOINT,
                Field::empty(),
            )],
            vec![],
        );
        let level = detach_level(&a, &b2, &[], &reg, &Assumptions::default()).expect("ok");
        assert_eq!(level, DetachLevel::None);
    }

    #[test]
    fn collusion_bounded_detects_pairs() {
        let reg = DomainRegistry::new();
        // d1 sees AMOUNT out of a; d2 sees AMOUNT into b. Individually fine;
        // colluding pair {d1, d2} joins by amount.
        let a = manifest(
            "x",
            vec![witness(
                WitnessRole::RelayOperator,
                "r1",
                &["d1"],
                Field::AMOUNT,
                Field::AMOUNT,
            )],
            vec![],
        );
        let b = manifest(
            "y",
            vec![witness(
                WitnessRole::Homeserver,
                "h1",
                &["d2"],
                Field::AMOUNT,
                Field::AMOUNT,
            )],
            vec![],
        );
        let asm1 = Assumptions {
            colluding_set_size: 1,
            ..Assumptions::default()
        };
        assert_eq!(
            detach_level(&a, &b, &[], &reg, &asm1).expect("ok"),
            DetachLevel::Independent
        );
        let asm2 = Assumptions {
            colluding_set_size: 2,
            ..Assumptions::default()
        };
        assert_eq!(
            detach_level(&a, &b, &[], &reg, &asm2).expect("ok"),
            DetachLevel::Independent
        );
        // AMOUNT is only visible out-of-a by d1 and into-b by d2: with k=2 the
        // pair sees AMOUNT on both sides => not CollusionBounded(2).
        let asm3 = Assumptions {
            colluding_set_size: 3,
            ..Assumptions::default()
        };
        assert_eq!(
            detach_level(&a, &b, &[], &reg, &asm3).expect("ok"),
            DetachLevel::Independent
        );
        // A clean case: disjoint kinds => CollusionBounded(2).
        let a2 = manifest(
            "x",
            vec![witness(
                WitnessRole::RelayOperator,
                "r1",
                &["d1"],
                Field::CONTENT_SIZE,
                Field::CONTENT_SIZE,
            )],
            vec![],
        );
        let b2 = manifest(
            "y",
            vec![witness(
                WitnessRole::Homeserver,
                "h1",
                &["d2"],
                Field::TIME,
                Field::TIME,
            )],
            vec![],
        );
        assert_eq!(
            detach_level(&a2, &b2, &[], &reg, &asm2).expect("ok"),
            DetachLevel::CollusionBounded(2)
        );
    }

    #[test]
    fn time_respects_window() {
        let reg = DomainRegistry::new();
        let t = spec(Field::TIME, "time.unix");
        let mut a = manifest("x", vec![], vec![t]);
        let b = manifest("y", vec![], vec![]);
        a.latency_bound_secs = Some(7200);
        let asm = Assumptions::default(); // window 3600
        assert_eq!(
            detach_level(&a, &b, &[], &reg, &asm).expect("ok"),
            DetachLevel::Independent
        );
        a.latency_bound_secs = Some(60);
        assert_eq!(
            detach_level(&a, &b, &[], &reg, &asm).expect("ok"),
            DetachLevel::None
        );
        a.latency_bound_secs = None; // unknown latency: conservatively within window
        assert_eq!(
            detach_level(&a, &b, &[], &reg, &asm).expect("ok"),
            DetachLevel::None
        );
    }

    #[test]
    fn join_kinds_filter_ignores_non_joinable_fields() {
        let reg = DomainRegistry::new();
        let a = manifest("x", vec![], vec![spec(Field::CONTENT_SIZE, "wire.bytes")]);
        let b = manifest("y", vec![], vec![]);
        let asm = Assumptions {
            join_kinds: Field::TRANSACTION_ID | Field::AMOUNT,
            ..Assumptions::default()
        };
        assert_eq!(
            detach_level(&a, &b, &[], &reg, &asm).expect("ok"),
            DetachLevel::Independent
        );
        assert_eq!(
            detach_level(&a, &b, &[], &reg, &Assumptions::default()).expect("ok"),
            DetachLevel::None
        );
    }

    #[test]
    fn correlator_fingerprint_is_stable_and_namespaced() {
        let s = spec(Field::TRANSACTION_ID, "lightning.payment_hash");
        let c1 = Correlator::new(s.clone(), b"abc");
        let c2 = Correlator::new(s.clone(), b"abc");
        assert_eq!(c1, c2);
        let c3 = Correlator::new(s.clone(), b"abd");
        assert_ne!(c1.fingerprint, c3.fingerprint);
        let s2 = spec(Field::TRANSACTION_ID, "swap.hash");
        let c4 = Correlator::new(s2, b"abc");
        assert_ne!(c1.fingerprint, c4.fingerprint);
        // Pinned vector (recorded in tests/vectors/molt_route_v1.json).
        assert_eq!(
            to_hex(&c1.fingerprint),
            "6c1658803ba17ef8d0a2bb1efc25e4ecb655e40b09c5ce03e4f53c1dfd487573"
        );
    }

    #[test]
    fn correlator_json_uses_hex_fingerprint() {
        let c = Correlator::new(spec(Field::AMOUNT, "btc.sats"), b"100000");
        let j = serde_json::to_string(&c).expect("ser");
        assert!(j.contains("\"fingerprint\":\""));
        let back: Correlator = serde_json::from_str(&j).expect("de");
        assert_eq!(back, c);
        let bad_hex = r#"{"spec":{"kind":"AMOUNT","namespace":"btc.sats"},"fingerprint":"zz"}"#;
        assert!(serde_json::from_str::<Correlator>(bad_hex).is_err());
        let bad_len = r#"{"spec":{"kind":"AMOUNT","namespace":"btc.sats"},"fingerprint":"abcd"}"#;
        assert!(serde_json::from_str::<Correlator>(bad_len).is_err());
    }

    #[test]
    fn trace_confirms_and_refutes_predicted_joins() {
        let s = spec(Field::TRANSACTION_ID, "lightning.payment_hash");
        let yes = RouteTrace {
            crossings: vec![
                (0, vec![Correlator::new(s.clone(), b"hash-A")]),
                (2, vec![Correlator::new(s.clone(), b"hash-A")]),
            ],
        };
        assert_eq!(yes.check_predicted_join(0, 2, &s), TraceVerdict::Confirmed);
        let no = RouteTrace {
            crossings: vec![
                (0, vec![Correlator::new(s.clone(), b"hash-A")]),
                (2, vec![Correlator::new(s.clone(), b"hash-B")]),
            ],
        };
        assert_eq!(no.check_predicted_join(0, 2, &s), TraceVerdict::Refuted);
        assert_eq!(
            no.check_predicted_join(0, 1, &s),
            TraceVerdict::InsufficientData
        );
        let other = spec(Field::AMOUNT, "btc.sats");
        assert_eq!(
            yes.check_predicted_join(0, 2, &other),
            TraceVerdict::InsufficientData
        );
    }

    #[test]
    fn cbor_is_deterministic_with_integer_keys() {
        let s = spec(Field::TRANSACTION_ID, "lightning.payment_hash");
        let cbor1 = s.to_cbor().expect("cbor");
        let cbor2 = spec(Field::TRANSACTION_ID, "lightning.payment_hash")
            .to_cbor()
            .expect("cbor");
        assert_eq!(cbor1, cbor2);
        // a2 00 1a 00 00 00 40  01 76 "lightning.payment_hash"
        assert_eq!(cbor1[0], 0xa2); // map(2)
        assert_eq!(cbor1[1], 0x00); // key 0
                                    // value is TRANSACTION_ID = 1<<6 = 64 => 0x18 0x40
        assert_eq!(&cbor1[2..4], &[0x18, 0x40]);
        assert_eq!(cbor1[4], 0x01); // key 1
        assert_eq!(cbor1[5], 0x76); // text(22)

        let seg = Segment {
            id: SegmentId("ln".into()),
            carries: vec![s.clone()],
        };
        let sc = seg.to_cbor().expect("cbor");
        assert_eq!(sc[0], 0xa2);
        let asm = Assumptions::default().to_cbor().expect("cbor");
        assert_eq!(asm[0], 0xa4); // map(4)
        let corr = Correlator::new(s, b"v").to_cbor().expect("cbor");
        assert_eq!(corr[0], 0xa2);
    }

    #[test]
    fn correlator_spec_rejects_bad_namespace() {
        assert!(CorrelatorSpec::new(Field::AMOUNT, "BTC SATS").is_err());
        assert!(CorrelatorSpec::new(Field::AMOUNT, "a..b").is_err());
        assert!(CorrelatorSpec::new(Field::AMOUNT, "btc.sats").is_ok());
    }
}
