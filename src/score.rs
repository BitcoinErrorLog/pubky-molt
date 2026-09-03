//! S7. Continuity-cost scorer.
//!
//! The question asked per domain (or colluding set) and per pair of
//! observation points is: **can it correlate the state before with the state
//! after, how confidently, and through which correlators?** Field count is
//! not privacy loss. Planning is static, so the scorer reasons over specs: if
//! a hop `preserves` a spec, the *same value* crosses that hop by
//! construction, so a join over it is [`Confidence::Exact`] for identifier
//! kinds and [`Confidence::High`]/[`Confidence::Statistical`] for
//! `AMOUNT`/`TIME`/`CONTENT_SIZE` within the assumptions' time window. Specs
//! carried by a [`crate::witness::Segment`] that is active at an observation
//! point are excluded from cost; everywhere else they count. A segment is
//! active across hop `i` if it is open across the boundary *into* hop `i`
//! or hop `i` opens it itself (opens apply before closes), so an adapter
//! that opens and closes a segment in a single hop (a Lightning path, a
//! bounded transfer step) is never charged for its own carried correlators.
//!
//! Observation points: point `0` is the input of hop `0`, point `p`
//! (`1..n`) is the boundary between hop `p-1` and hop `p`, and point `n` is
//! the output of the last hop. A domain observes the union of the relevant
//! witnesses' `learns_in`/`learns_out` at each point. Where a spec is known
//! for an observed kind (an adjacent hop preserves it), the scorer matches
//! on the full [`CorrelatorSpec`] — kind *and* namespace — so
//! `{TRANSACTION_ID, "lightning.payment_hash"}` and
//! `{TRANSACTION_ID, "bitcoin.txid"}` are never conflated; only observed
//! kinds with no known spec fall back to field-only matching.

use crate::planner::RejectReason;
use crate::route::{Adapter, Amount, Route};
use crate::witness::{
    detach_level, detach_level_scoped, Assumptions, CorrelatorSpec, DetachLevel, DomainRegistry,
    Field, Manifest, ObservationDomain, Segment, SegmentViolation,
};
use crate::{MoltError, PurposeId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Caller preference weights. How the components combine is caller policy;
/// presets below are sensible defaults, recorded in the vectors.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Weights {
    /// Weight on continuity cost (privacy).
    pub continuity: f32,
    /// Weight on reduced monetary/resource cost.
    pub cost: f32,
    /// Weight on latency.
    pub latency: f32,
}

/// Prefer low latency.
pub const FAST: Weights = Weights {
    continuity: 0.2,
    cost: 0.3,
    latency: 0.5,
};
/// Prefer low cost.
pub const CHEAP: Weights = Weights {
    continuity: 0.2,
    cost: 0.6,
    latency: 0.2,
};
/// Prefer privacy, balanced otherwise.
pub const PRIVATE: Weights = Weights {
    continuity: 0.7,
    cost: 0.2,
    latency: 0.1,
};
/// Minimize continuity only; cost and latency ignored.
pub const MAX_DETACH: Weights = Weights {
    continuity: 1.0,
    cost: 0.0,
    latency: 0.0,
};

impl Weights {
    /// Whether all components are finite and non-negative.
    pub fn is_valid(&self) -> bool {
        [self.continuity, self.cost, self.latency]
            .iter()
            .all(|x| x.is_finite() && *x >= 0.0)
    }
}

/// Caller-supplied reduction of heterogeneous costs to one comparable
/// number. Molt ships no default that assumes an asset.
pub trait CostPolicy: Send + Sync {
    /// Reduce a route's quoted costs to one number, or reject the route.
    fn reduce(&self, costs: &[Amount]) -> Result<f32, MoltError>;
}

/// A [`CostPolicy`] for callers that only ever see one asset: sums the
/// values of costs in `asset`/`units`, and rejects any route quoting
/// anything else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleAsset {
    /// The only accepted asset (e.g. `"BTC"`).
    pub asset: String,
    /// The only accepted units (e.g. `"sat"`).
    pub units: String,
}

impl SingleAsset {
    /// Construct a policy for `asset`/`units`.
    pub fn new(asset: &str, units: &str) -> Self {
        SingleAsset {
            asset: asset.into(),
            units: units.into(),
        }
    }
}

impl CostPolicy for SingleAsset {
    fn reduce(&self, costs: &[Amount]) -> Result<f32, MoltError> {
        let mut total: u128 = 0;
        for c in costs {
            if c.asset != self.asset || c.units != self.units {
                return Err(MoltError::CostPolicyRejected(format!(
                    "SingleAsset({},{}) cannot price {} {}",
                    self.asset, self.units, c.asset, c.units
                )));
            }
            total = total.saturating_add(c.value);
        }
        Ok(total as f32)
    }
}

/// How confidently a domain set can perform a join.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    /// Size/timing pattern only.
    Statistical,
    /// Unique fingerprint, e.g. exact amount+time within the window.
    High,
    /// Identical identifier (value continuous by construction).
    Exact,
}

impl Confidence {
    /// Numeric weight: `Exact = 1.0`, `High = 0.8`, `Statistical = 0.3`
    /// (defaults; tunable, recorded in vectors).
    pub fn weight(self) -> f32 {
        match self {
            Confidence::Exact => 1.0,
            Confidence::High => 0.8,
            Confidence::Statistical => 0.3,
        }
    }
}

/// One predicted join: `domain_set` can correlate observation points
/// `joins` (boundary index pairs) via correlator kinds `via`, with
/// `confidence`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JoinReport {
    /// The (possibly colluding) domains performing the join.
    pub domain_set: Vec<ObservationDomain>,
    /// Observation-point index pairs `(i, j)`, `i < j`.
    pub joins: Vec<(usize, usize)>,
    /// The correlator kinds the join goes through.
    pub via: Vec<CorrelatorSpec>,
    /// How confident the join is.
    pub confidence: Confidence,
}

/// The score of one route.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RouteScore {
    /// `Σ_{S : |S| ≤ k} w(|S|) · Σ_{joins(S)} severity(via.kind) ·
    /// c(confidence) − Σ detach_bonus(level)`, clamped at `0`, then scaled by
    /// `Weights.continuity` (see [`score`]).
    pub continuity_cost: f32,
    /// Every predicted join, with confidence and correlators.
    pub joins: Vec<JoinReport>,
    /// Detach level of each hop's in→out crossing (`detaches[i]` is hop `i`).
    pub detaches: Vec<DetachLevel>,
    /// All quoted costs, unreduced.
    pub costs: Vec<Amount>,
    /// The [`CostPolicy`]-reduced cost.
    pub reduced_cost: f32,
    /// Total quoted latency.
    pub latency_secs: u32,
}

impl RouteScore {
    /// Combine the components under `w`. `continuity_cost` is already scaled
    /// by `w.continuity` inside [`score`]; `total` adds the cost and latency
    /// terms.
    pub fn total(&self, w: &Weights) -> f32 {
        self.continuity_cost + w.cost * self.reduced_cost + w.latency * self.latency_secs as f32
    }
}

/// Why a route cannot be ranked at all. An `Err` is not a bad score; it
/// means the route is ineligible.
#[derive(Clone, Debug, PartialEq, thiserror::Error, Serialize, Deserialize)]
pub enum ScoreError {
    /// A segment continuity requirement was violated.
    #[error("segment violation: {0}")]
    Violation(SegmentViolation),
    /// The [`CostPolicy`] rejected this route's quotes.
    #[error("cost policy: {0}")]
    Cost(MoltError),
    /// The route is structurally unplannable (inconsistent bookkeeping).
    #[error("unplannable: {0:?}")]
    Unplannable(RejectReason),
}

/// Severity of a join through `kind`.
///
/// `ROOT_IDENTITY`-involving ≫ `RELATIONSHIP_IDENTITY` ≫ identifier kinds
/// (`NETWORK_IDENTIFIER`/`SESSION_IDENTIFIER`/`TRANSACTION_ID`/
/// `OBLIGATION_ID`) > `AMOUNT`/`TIME` fingerprints > `RELATIONSHIP_LINK` >
/// `CONTENT_SIZE`. Unlisted kinds default to `1.0` (recorded in DECISIONS).
pub fn severity(kind: Field) -> f32 {
    if kind.contains(Field::ROOT_IDENTITY) {
        100.0
    } else if kind.contains(Field::RELATIONSHIP_IDENTITY) {
        25.0
    } else if kind.contains(Field::PAIRWISE_KEY) {
        20.0
    } else if kind.intersects(
        Field::NETWORK_IDENTIFIER
            | Field::SESSION_IDENTIFIER
            | Field::TRANSACTION_ID
            | Field::OBLIGATION_ID,
    ) {
        10.0
    } else if kind.intersects(Field::AMOUNT | Field::TIME | Field::DENOMINATION) {
        5.0
    } else if kind.contains(Field::RELATIONSHIP_LINK) {
        2.0
    } else {
        1.0
    }
}

/// Colluding-set weight `w(|S|) = 1/|S|` (defaults; recorded in vectors).
pub fn set_weight(set_size: usize) -> f32 {
    1.0 / set_size.max(1) as f32
}

/// Detach bonus per boundary: `None = 0`, `Unknown = 0.1`,
/// `Independent = 1.0`, `CollusionBounded(k) = 1.0 + 0.5k` (defaults;
/// recorded in vectors).
pub fn detach_bonus(level: DetachLevel) -> f32 {
    match level {
        DetachLevel::None => 0.0,
        DetachLevel::Unknown => 0.1,
        DetachLevel::Independent => 1.0,
        DetachLevel::CollusionBounded(k) => 1.0 + 0.5 * k as f32,
    }
}

/// Domain → observed kinds at one observation point.
fn point_kinds(
    manifests: &[&Manifest],
    point: usize,
    reg: &DomainRegistry,
) -> BTreeMap<ObservationDomain, Field> {
    let n = manifests.len();
    let mut out: BTreeMap<ObservationDomain, Field> = BTreeMap::new();
    if point == 0 {
        for w in &manifests[0].witnesses {
            add_learns(&mut out, w, w.learns_in, reg);
        }
    } else if point == n {
        for w in &manifests[n - 1].witnesses {
            add_learns(&mut out, w, w.learns_out, reg);
        }
    } else {
        for w in &manifests[point - 1].witnesses {
            add_learns(&mut out, w, w.learns_out, reg);
        }
        for w in &manifests[point].witnesses {
            add_learns(&mut out, w, w.learns_in, reg);
        }
    }
    out
}

fn add_learns(
    out: &mut BTreeMap<ObservationDomain, Field>,
    w: &crate::witness::Witness,
    kinds: Field,
    reg: &DomainRegistry,
) {
    let mut domains: BTreeSet<ObservationDomain> = w.domains.iter().cloned().collect();
    domains.extend(reg.domains_for(&w.operator));
    for d in domains {
        out.entry(d).and_modify(|k| *k |= kinds).or_insert(kinds);
    }
}

/// Domain → observed correlator specs at one observation point.
///
/// A domain observing a kind for which an adjacent hop declares a matching
/// `preserves` entry observes that *spec* (kind + namespace); a kind with no
/// known spec yields a field-only entry (empty namespace). This keeps
/// namespaces in the scoring wherever they are known, so the same kind in
/// two different namespaces is never conflated.
fn point_specs(
    manifests: &[&Manifest],
    point: usize,
    reg: &DomainRegistry,
) -> BTreeMap<ObservationDomain, BTreeSet<CorrelatorSpec>> {
    let kinds = point_kinds(manifests, point, reg);
    let n = manifests.len();
    let adjacent: [&Manifest; 2] = if point == 0 {
        [manifests[0], manifests[0]]
    } else if point == n {
        [manifests[n - 1], manifests[n - 1]]
    } else {
        [manifests[point - 1], manifests[point]]
    };
    let mut out: BTreeMap<ObservationDomain, BTreeSet<CorrelatorSpec>> = BTreeMap::new();
    for (dom, ks) in kinds {
        let mut set = BTreeSet::new();
        for f in ks.iter() {
            let mut known = false;
            for m in adjacent {
                for p in &m.preserves {
                    if p.kind.contains(f) {
                        set.insert(CorrelatorSpec {
                            kind: f,
                            namespace: p.namespace.clone(),
                        });
                        known = true;
                    }
                }
            }
            if !known {
                set.insert(CorrelatorSpec {
                    kind: f,
                    namespace: String::new(),
                });
            }
        }
        out.insert(dom, set);
    }
    out
}

/// Specs carried by segments open across observation point `p` (`1..=n`).
fn carried_specs_at(open_at: &[Vec<Segment>], point: usize) -> Vec<CorrelatorSpec> {
    if point == 0 || point > open_at.len() {
        return Vec::new();
    }
    open_at[point - 1]
        .iter()
        .flat_map(|s| s.carries.iter().cloned())
        .collect()
}

/// Is `spec` excluded from a hop-local join or leak because an active
/// segment carries it? Mirrors [`crate::witness`]'s leak-exclusion rule: a
/// known spec is excluded only by a carried spec of the same kind *and*
/// namespace; a field-only observation (empty namespace) is excluded by any
/// carried spec of the same kind.
fn excluded_by_active(spec: &CorrelatorSpec, active_carries: &[CorrelatorSpec]) -> bool {
    active_carries.iter().any(|c| {
        c.kind.contains(spec.kind) && (spec.namespace.is_empty() || c.namespace == spec.namespace)
    })
}

/// Is `spec` preserved (value-continuous, same kind *and* namespace) across
/// every hop in `from..to`?
fn spec_continuous_across(
    manifests: &[&Manifest],
    from: usize,
    to: usize,
    spec: &CorrelatorSpec,
) -> bool {
    (from..to).all(|h| {
        manifests[h]
            .preserves
            .iter()
            .any(|p| p.kind.contains(spec.kind) && p.namespace == spec.namespace)
    })
}

/// Are observations at points `i` and `j` within the assumptions' window?
/// Hops with no declared latency bound are conservatively treated as instant
/// (within the window).
fn within_window(manifests: &[&Manifest], i: usize, j: usize, asm: &Assumptions) -> bool {
    let latency: u64 = (i..j)
        .map(|h| manifests[h].latency_bound_secs.unwrap_or(0) as u64)
        .sum();
    latency <= asm.time_window_secs as u64
}

/// Confidence of a join through `spec` between points `i` and `j`.
///
/// A value-continuous known spec (preserved, same namespace, at every hop in
/// `i..j`) joins at `Exact` for identifier kinds and at `High` for
/// `AMOUNT`/`TIME`/`DENOMINATION` within the window. Everything else —
/// including `CONTENT_SIZE` and every field-only observation — is
/// `Statistical`.
fn join_confidence(
    manifests: &[&Manifest],
    i: usize,
    j: usize,
    spec: &CorrelatorSpec,
    asm: &Assumptions,
) -> Confidence {
    let continuous = !spec.namespace.is_empty() && spec_continuous_across(manifests, i, j, spec);
    let identifiers = Field::ROOT_IDENTITY
        | Field::RELATIONSHIP_IDENTITY
        | Field::PAIRWISE_KEY
        | Field::NETWORK_IDENTIFIER
        | Field::SESSION_IDENTIFIER
        | Field::TRANSACTION_ID
        | Field::OBLIGATION_ID
        | Field::SOURCE_ENDPOINT
        | Field::DEST_ENDPOINT
        | Field::CONTEXT_ID;
    let windowed = Field::AMOUNT | Field::TIME | Field::DENOMINATION;
    if continuous && spec.kind.intersects(identifiers) {
        Confidence::Exact
    } else if continuous && spec.kind.intersects(windowed) && within_window(manifests, i, j, asm) {
        Confidence::High
    } else {
        Confidence::Statistical
    }
}

/// Score a route. `Err` means the route cannot be ranked at all (segment
/// violation, cost-policy rejection, inconsistent bookkeeping); it is not a
/// bad score.
///
/// The route must have been built against the same `adapters` (a hop with no
/// matching adapter is reported as [`ScoreError::Unplannable`]). The stored
/// `continuity_cost` is the raw continuity cost scaled by `w.continuity`, so
/// the four [`Weights`] presets produce comparable preference numbers via
/// [`RouteScore::total`].
pub fn score(
    route: &Route,
    adapters: &[&dyn Adapter],
    reg: &DomainRegistry,
    asm: &Assumptions,
    w: &Weights,
    cost: &dyn CostPolicy,
) -> Result<RouteScore, ScoreError> {
    if !w.is_valid() {
        return Err(ScoreError::Cost(MoltError::CostPolicyRejected(
            "weights must be finite and non-negative".into(),
        )));
    }
    if route.states.len() != route.hops.len() + 1
        || route.open_segments_at.len() != route.hops.len()
    {
        return Err(ScoreError::Unplannable(RejectReason::DepthExceeded));
    }
    if let Some(seg) = route.open_segments().first() {
        return Err(ScoreError::Unplannable(RejectReason::UnclosedSegment(
            seg.id.clone(),
        )));
    }

    let mut manifests: Vec<&Manifest> = Vec::with_capacity(route.hops.len());
    let mut owned: Vec<Manifest> = Vec::with_capacity(route.hops.len());
    let mut effects = Vec::with_capacity(route.hops.len());
    let mut costs: Vec<Amount> = Vec::new();
    let mut latency_secs: u32 = 0;
    for (i, hop) in route.hops.iter().enumerate() {
        let ad = adapters.iter().find(|a| a.id() == hop).ok_or_else(|| {
            ScoreError::Unplannable(RejectReason::UnsupportedConstraint {
                namespace: PurposeId::internal("pubky.molt.score.v1"),
                adapter: hop.clone(),
            })
        })?;
        owned.push(ad.manifest());
        effects.push(ad.segments());
        let q = ad.quote(&route.states[i]);
        costs.extend(q.costs);
        latency_secs = latency_secs.saturating_add(q.latency_secs);
    }
    for m in &owned {
        manifests.push(m);
    }

    // Detach levels: detaches[i] is hop i's own in→out crossing. Segments
    // that continue through hop i must have their carries preserved by it.
    // The exclusion set is the per-hop ACTIVE set: every segment open across
    // the boundary into hop i, plus hop i's own opens (opens apply before
    // closes). A hop that opens and closes a segment in one hop is therefore
    // not charged a leak for the correlators it carries inside that segment.
    let mut detaches = Vec::with_capacity(route.hops.len());
    for (i, m) in manifests.iter().enumerate() {
        let inbound: &[Segment] = if i == 0 {
            &[]
        } else {
            &route.open_segments_at[i - 1]
        };
        let continuing: Vec<Segment> = inbound
            .iter()
            .filter(|s| effects[i].continues.contains(&s.id))
            .cloned()
            .collect();
        let active: Vec<Segment> = inbound
            .iter()
            .cloned()
            .chain(effects[i].opens.iter().cloned())
            .collect();
        detaches.push(
            detach_level_scoped(m, m, &continuing, &active, reg, asm)
                .map_err(ScoreError::Violation)?,
        );
    }
    // Internal composition boundaries: structural violation check.
    for i in 1..manifests.len() {
        detach_level(
            manifests[i - 1],
            manifests[i],
            &route.open_segments_at[i - 1],
            reg,
            asm,
        )
        .map_err(ScoreError::Violation)?;
    }

    // Observation points 0..=n.
    let n = route.hops.len();
    let points: Vec<BTreeMap<ObservationDomain, BTreeSet<CorrelatorSpec>>> =
        (0..=n).map(|p| point_specs(&manifests, p, reg)).collect();

    // Join enumeration over minimal domain sets of size <= colluding_set_size.
    let mut joins: Vec<JoinReport> = Vec::new();
    let mut reported_sets: BTreeMap<(usize, usize), Vec<BTreeSet<ObservationDomain>>> =
        BTreeMap::new();
    let all_domains: BTreeSet<ObservationDomain> =
        points.iter().flat_map(|p| p.keys().cloned()).collect();
    let domains: Vec<ObservationDomain> = all_domains.into_iter().collect();
    let max_k = (asm.colluding_set_size as usize).min(domains.len()).max(1);
    for i in 0..=n {
        for j in (i + 1)..=n {
            // Exclusion set: specs carried by segments open across either
            // boundary point, plus — for the hop-local pair (i, i+1) — the
            // specs hop i opens and closes itself (the ACTIVE set of hop i).
            let mut excluded = carried_specs_at(&route.open_segments_at, i);
            excluded.extend(carried_specs_at(&route.open_segments_at, j));
            if j == i + 1 {
                excluded.extend(
                    effects[i]
                        .opens
                        .iter()
                        .flat_map(|s| s.carries.iter().cloned()),
                );
            }
            for k in 1..=max_k {
                for subset_idx in combinations(domains.len(), k) {
                    let subset: BTreeSet<ObservationDomain> =
                        subset_idx.iter().map(|&x| domains[x].clone()).collect();
                    // Minimality: skip if an already-reported set for (i, j)
                    // is a proper subset of this one.
                    let dominated = reported_sets
                        .get(&(i, j))
                        .map(|sets| {
                            sets.iter()
                                .any(|s| s.len() < subset.len() && s.is_subset(&subset))
                        })
                        .unwrap_or(false);
                    if dominated {
                        continue;
                    }
                    let empty: BTreeSet<CorrelatorSpec> = BTreeSet::new();
                    let si: BTreeSet<&CorrelatorSpec> = subset_idx
                        .iter()
                        .flat_map(|&x| points[i].get(&domains[x]).unwrap_or(&empty).iter())
                        .collect();
                    let sj: BTreeSet<&CorrelatorSpec> = subset_idx
                        .iter()
                        .flat_map(|&x| points[j].get(&domains[x]).unwrap_or(&empty).iter())
                        .collect();
                    let mut via: BTreeSet<CorrelatorSpec> = BTreeSet::new();
                    let mut conf = Confidence::Statistical;
                    for a in &si {
                        for b in &sj {
                            if !a.kind.intersects(b.kind) {
                                continue;
                            }
                            let kind = a.kind & b.kind;
                            if !kind.intersects(asm.join_kinds) {
                                continue;
                            }
                            // AMOUNT/TIME joins exist only within the time
                            // window; CONTENT_SIZE (and everything else) is
                            // matched regardless of the window.
                            if kind.intersects(Field::AMOUNT | Field::TIME)
                                && !within_window(&manifests, i, j, asm)
                            {
                                continue;
                            }
                            let a_known = !a.namespace.is_empty();
                            let b_known = !b.namespace.is_empty();
                            if a_known && b_known && a.namespace != b.namespace {
                                // Same kind, different namespaces: the value
                                // is transformed between the points; no join.
                                continue;
                            }
                            let spec = CorrelatorSpec {
                                kind,
                                namespace: if a_known && b_known {
                                    a.namespace.clone()
                                } else {
                                    String::new()
                                },
                            };
                            if excluded_by_active(&spec, &excluded) {
                                continue;
                            }
                            conf = conf.max(join_confidence(&manifests, i, j, &spec, asm));
                            via.insert(spec);
                        }
                    }
                    if via.is_empty() {
                        continue;
                    }
                    reported_sets
                        .entry((i, j))
                        .or_default()
                        .push(subset.clone());
                    joins.push(JoinReport {
                        domain_set: subset.into_iter().collect(),
                        joins: vec![(i, j)],
                        via: via.into_iter().collect(),
                        confidence: conf,
                    });
                }
            }
        }
    }
    joins.sort_by(|a, b| {
        a.joins
            .cmp(&b.joins)
            .then_with(|| a.domain_set.cmp(&b.domain_set))
            .then_with(|| a.via.cmp(&b.via))
    });

    let raw: f32 = joins
        .iter()
        .map(|jr| {
            let sev = jr
                .via
                .iter()
                .map(|v| severity(v.kind))
                .fold(0.0_f32, f32::max);
            set_weight(jr.domain_set.len()) * sev * jr.confidence.weight()
        })
        .sum::<f32>()
        - detaches.iter().map(|d| detach_bonus(*d)).sum::<f32>();
    let continuity_cost = raw.max(0.0) * w.continuity;

    let reduced_cost = cost.reduce(&costs).map_err(ScoreError::Cost)?;

    Ok(RouteScore {
        continuity_cost,
        joins,
        detaches,
        costs,
        reduced_cost,
        latency_secs,
    })
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::{Holder, Quote, RecoverySemantics, RouteState};
    use crate::witness::{OperatorId, SegmentEffects, SegmentId, Witness, WitnessRole};

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

    struct HopAdapter {
        id: String,
        manifest: Manifest,
        effects: SegmentEffects,
        costs: Vec<Amount>,
    }

    impl Adapter for HopAdapter {
        fn id(&self) -> &str {
            &self.id
        }
        fn accepts(&self, _s: &RouteState) -> bool {
            true
        }
        fn produces(&self, s: &RouteState) -> Option<RouteState> {
            Some(s.clone())
        }
        fn manifest(&self) -> Manifest {
            self.manifest.clone()
        }
        fn quote(&self, _s: &RouteState) -> Quote {
            Quote {
                costs: self.costs.clone(),
                latency_secs: 5,
            }
        }
        fn recovery(&self) -> RecoverySemantics {
            RecoverySemantics::Atomic
        }
        fn segments(&self) -> SegmentEffects {
            self.effects.clone()
        }
    }

    fn s() -> RouteState {
        RouteState::Value {
            network: "n".into(),
            amount: None,
            holder: Holder::Self_,
        }
    }

    fn one_hop(manifest: Manifest) -> (Route, HopAdapter) {
        let ad = HopAdapter {
            id: "h".into(),
            manifest,
            effects: SegmentEffects::default(),
            costs: vec![],
        };
        let route = Route {
            hops: vec!["h".into()],
            states: vec![s(), s()],
            open_segments_at: vec![vec![]],
        };
        (route, ad)
    }

    #[test]
    fn weights_presets_sum_to_one() {
        for w in [FAST, CHEAP, PRIVATE, MAX_DETACH] {
            assert!(w.is_valid());
            let sum = w.continuity + w.cost + w.latency;
            assert!((sum - 1.0).abs() < 1e-6, "sum {sum}");
        }
        let bad = Weights {
            continuity: -1.0,
            cost: 0.0,
            latency: 0.0,
        };
        assert!(!bad.is_valid());
    }

    #[test]
    fn single_asset_sums_and_rejects_foreign_assets() {
        let pol = SingleAsset::new("BTC", "sat");
        let costs = vec![
            Amount {
                asset: "BTC".into(),
                units: "sat".into(),
                value: 100,
            },
            Amount {
                asset: "BTC".into(),
                units: "sat".into(),
                value: 23,
            },
        ];
        assert_eq!(pol.reduce(&costs).expect("reduce"), 123.0);
        assert_eq!(pol.reduce(&[]).expect("empty"), 0.0);
        let mixed = vec![Amount {
            asset: "USD".into(),
            units: "cent".into(),
            value: 5,
        }];
        assert!(pol.reduce(&mixed).is_err());
    }

    #[test]
    fn severity_and_confidence_and_bonus_tables() {
        assert!(severity(Field::ROOT_IDENTITY) > severity(Field::RELATIONSHIP_IDENTITY));
        assert!(severity(Field::RELATIONSHIP_IDENTITY) > severity(Field::TRANSACTION_ID));
        assert!(severity(Field::TRANSACTION_ID) > severity(Field::AMOUNT));
        assert!(severity(Field::AMOUNT) > severity(Field::RELATIONSHIP_LINK));
        assert!(severity(Field::RELATIONSHIP_LINK) > severity(Field::CONTENT_SIZE));
        assert_eq!(Confidence::Exact.weight(), 1.0);
        assert_eq!(Confidence::High.weight(), 0.8);
        assert_eq!(Confidence::Statistical.weight(), 0.3);
        assert_eq!(detach_bonus(DetachLevel::None), 0.0);
        assert_eq!(detach_bonus(DetachLevel::CollusionBounded(2)), 2.0);
        assert_eq!(set_weight(2), 0.5);
    }

    #[test]
    fn score_reports_high_confidence_amount_join() {
        // Chain observer sees AMOUNT|TIME on both sides; hop preserves both.
        let m = Manifest {
            adapter_id: "h".into(),
            witnesses: vec![witness(
                WitnessRole::Chain,
                "chain",
                &["chain-obs"],
                Field::NETWORK_IDENTIFIER | Field::AMOUNT | Field::TIME,
                Field::NETWORK_IDENTIFIER | Field::AMOUNT | Field::TIME,
            )],
            preserves: vec![
                CorrelatorSpec::new(Field::AMOUNT, "btc.sats").expect("spec"),
                CorrelatorSpec::new(Field::TIME, "time.unix").expect("spec"),
            ],
            latency_bound_secs: Some(60),
        };
        let (route, ad) = one_hop(m);
        let adapters: Vec<&dyn Adapter> = vec![&ad];
        let score = score(
            &route,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &PRIVATE,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect("score");
        assert!(!score.joins.is_empty());
        let j = &score.joins[0];
        assert_eq!(j.domain_set, vec![ObservationDomain("chain-obs".into())]);
        assert_eq!(j.joins, vec![(0, 1)]);
        assert_eq!(j.confidence, Confidence::High);
        assert!(score.continuity_cost > 0.0);
        assert_eq!(score.detaches, vec![DetachLevel::None]);
    }

    #[test]
    fn score_exact_join_when_identifier_preserved() {
        let m = Manifest {
            adapter_id: "h".into(),
            witnesses: vec![witness(
                WitnessRole::LnPeer,
                "ln",
                &["ln-net"],
                Field::TRANSACTION_ID,
                Field::TRANSACTION_ID,
            )],
            preserves: vec![
                CorrelatorSpec::new(Field::TRANSACTION_ID, "lightning.payment_hash").expect("spec"),
            ],
            latency_bound_secs: Some(60),
        };
        let (route, ad) = one_hop(m);
        let adapters: Vec<&dyn Adapter> = vec![&ad];
        let score = score(
            &route,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &MAX_DETACH,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect("score");
        assert_eq!(score.joins[0].confidence, Confidence::Exact);
        assert_eq!(score.joins[0].via[0].namespace, "lightning.payment_hash");
    }

    #[test]
    fn score_err_on_single_asset_mismatch_and_ok_on_multi_asset() {
        let m = Manifest {
            adapter_id: "h".into(),
            witnesses: vec![],
            preserves: vec![],
            latency_bound_secs: Some(1),
        };
        let (route, mut ad) = one_hop(m);
        ad.costs = vec![
            Amount {
                asset: "BTC".into(),
                units: "sat".into(),
                value: 10,
            },
            Amount {
                asset: "USD".into(),
                units: "cent".into(),
                value: 5,
            },
        ];
        let adapters: Vec<&dyn Adapter> = vec![&ad];
        let err = score(
            &route,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &PRIVATE,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect_err("must reject mixed assets");
        assert!(matches!(err, ScoreError::Cost(_)));

        struct Multi;
        impl CostPolicy for Multi {
            fn reduce(&self, costs: &[Amount]) -> Result<f32, MoltError> {
                // Test policy: 1 USD cent == 1 sat for comparison purposes only.
                Ok(costs.iter().map(|c| c.value as f32).sum())
            }
        }
        let ok = score(
            &route,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &PRIVATE,
            &Multi,
        )
        .expect("multi-asset policy accepts");
        assert_eq!(ok.reduced_cost, 15.0);
        assert_eq!(ok.costs.len(), 2);
        assert_eq!(ok.latency_secs, 5);
    }

    #[test]
    fn score_unplannable_on_bad_bookkeeping() {
        let (mut route, ad) = one_hop(Manifest {
            adapter_id: "h".into(),
            witnesses: vec![],
            preserves: vec![],
            latency_bound_secs: None,
        });
        let adapters: Vec<&dyn Adapter> = vec![&ad];
        // open segment left at the end
        route.open_segments_at = vec![vec![Segment {
            id: SegmentId("x".into()),
            carries: vec![CorrelatorSpec::new(Field::TRANSACTION_ID, "swap.hash").expect("spec")],
        }]];
        let err = score(
            &route,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &PRIVATE,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect_err("unclosed segment");
        assert!(matches!(
            err,
            ScoreError::Unplannable(RejectReason::UnclosedSegment(_))
        ));

        // unknown adapter id
        let route2 = Route {
            hops: vec!["ghost".into()],
            states: vec![s(), s()],
            open_segments_at: vec![vec![]],
        };
        let err2 = score(
            &route2,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &PRIVATE,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect_err("unknown adapter");
        assert!(matches!(
            err2,
            ScoreError::Unplannable(RejectReason::UnsupportedConstraint { .. })
        ));
    }

    #[test]
    fn score_violation_when_continued_segment_not_preserved() {
        // Two hops; a segment open across the internal boundary continues
        // through hop 2, whose manifest does not preserve its carries.
        let ph =
            CorrelatorSpec::new(Field::TRANSACTION_ID, "lightning.payment_hash").expect("spec");
        let m1 = Manifest {
            adapter_id: "h1".into(),
            witnesses: vec![],
            preserves: vec![ph.clone()],
            latency_bound_secs: Some(1),
        };
        let m2 = Manifest {
            adapter_id: "h2".into(),
            witnesses: vec![],
            preserves: vec![],
            latency_bound_secs: Some(1),
        };
        let seg = Segment {
            id: SegmentId("ln".into()),
            carries: vec![ph],
        };
        let a1 = HopAdapter {
            id: "h1".into(),
            manifest: m1,
            effects: SegmentEffects {
                opens: vec![seg.clone()],
                continues: vec![],
                closes: vec![],
            },
            costs: vec![],
        };
        let a2 = HopAdapter {
            id: "h2".into(),
            manifest: m2,
            effects: SegmentEffects {
                opens: vec![],
                continues: vec![SegmentId("ln".into())],
                closes: vec![SegmentId("ln".into())],
            },
            costs: vec![],
        };
        let route = Route {
            hops: vec!["h1".into(), "h2".into()],
            states: vec![s(), s(), s()],
            open_segments_at: vec![vec![seg], vec![]],
        };
        let adapters: Vec<&dyn Adapter> = vec![&a1, &a2];
        let err = score(
            &route,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &PRIVATE,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect_err("violation");
        assert!(matches!(err, ScoreError::Violation(ref v) if v.segment.0 == "ln"));
    }

    #[test]
    fn open_segment_excludes_kind_from_join_cost() {
        // Relay domain sees NETWORK_IDENTIFIER at points 0 and 1; with a
        // segment open across point 1 carrying that kind, the join vanishes.
        let mk_manifest = |id: &str| Manifest {
            adapter_id: id.into(),
            witnesses: vec![witness(
                WitnessRole::RelayOperator,
                "r",
                &["relay-co"],
                Field::NETWORK_IDENTIFIER,
                Field::NETWORK_IDENTIFIER,
            )],
            preserves: vec![
                CorrelatorSpec::new(Field::NETWORK_IDENTIFIER, "noise.session_id").expect("spec"),
            ],
            latency_bound_secs: Some(1),
        };
        let a1 = HopAdapter {
            id: "h1".into(),
            manifest: mk_manifest("h1"),
            effects: SegmentEffects::default(),
            costs: vec![],
        };
        let a2 = HopAdapter {
            id: "h2".into(),
            manifest: mk_manifest("h2"),
            effects: SegmentEffects::default(),
            costs: vec![],
        };
        let base = Route {
            hops: vec!["h1".into(), "h2".into()],
            states: vec![s(), s(), s()],
            open_segments_at: vec![vec![], vec![]],
        };
        let adapters: Vec<&dyn Adapter> = vec![&a1, &a2];
        let with_join = score(
            &base,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &MAX_DETACH,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect("score");
        assert!(!with_join.joins.is_empty());

        let seg = Segment {
            id: SegmentId("sess".into()),
            carries: vec![
                CorrelatorSpec::new(Field::NETWORK_IDENTIFIER, "noise.session_id").expect("spec"),
            ],
        };
        let covered = Route {
            open_segments_at: vec![vec![seg], vec![]],
            ..base.clone()
        };
        let without = score(
            &covered,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &MAX_DETACH,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect("score");
        // Joins touching the covered boundary (0,1) and (1,2) are excluded
        // inside the open segment; the join spanning the whole segment (0,2)
        // remains: the value crossing past the close is exactly the scored
        // "leak past a close" case.
        let pairs: Vec<(usize, usize)> =
            without.joins.iter().flat_map(|j| j.joins.clone()).collect();
        assert!(
            !pairs.contains(&(0, 1)),
            "join inside open segment must be excluded: {:?}",
            without.joins
        );
        assert!(
            !pairs.contains(&(1, 2)),
            "join inside open segment must be excluded: {:?}",
            without.joins
        );
        assert!(
            pairs.contains(&(0, 2)),
            "join spanning a closed segment is the scored leak: {:?}",
            without.joins
        );
    }

    #[test]
    fn same_hop_open_close_segment_excludes_carried_correlators() {
        // An adapter that opens AND closes a segment in one hop (LightningPath,
        // BoundedTransferStep) must not have its own carried correlators
        // charged as leaks or joins.
        let ph =
            CorrelatorSpec::new(Field::TRANSACTION_ID, "lightning.payment_hash").expect("spec");
        let receipt = CorrelatorSpec::new(Field::OBLIGATION_ID, "credit.receipt_id").expect("spec");
        let ln = HopAdapter {
            id: "ln".into(),
            manifest: Manifest {
                adapter_id: "ln".into(),
                witnesses: vec![witness(
                    WitnessRole::LnPeer,
                    "ln",
                    &["ln-net"],
                    Field::TRANSACTION_ID,
                    Field::TRANSACTION_ID,
                )],
                preserves: vec![],
                latency_bound_secs: Some(30),
            },
            effects: SegmentEffects {
                opens: vec![Segment {
                    id: SegmentId("ln".into()),
                    carries: vec![ph.clone()],
                }],
                continues: vec![],
                closes: vec![SegmentId("ln".into())],
            },
            costs: vec![],
        };
        let bts = HopAdapter {
            id: "bts".into(),
            manifest: Manifest {
                adapter_id: "bts".into(),
                witnesses: vec![witness(
                    WitnessRole::Intermediary,
                    "ch",
                    &["clearing-house"],
                    Field::OBLIGATION_ID,
                    Field::OBLIGATION_ID,
                )],
                preserves: vec![],
                latency_bound_secs: Some(5),
            },
            effects: SegmentEffects {
                opens: vec![Segment {
                    id: SegmentId("step".into()),
                    carries: vec![receipt.clone()],
                }],
                continues: vec![],
                closes: vec![SegmentId("step".into())],
            },
            costs: vec![],
        };
        for ad in [&ln, &bts] {
            let route = Route {
                hops: vec![ad.id().to_string()],
                states: vec![s(), s()],
                open_segments_at: vec![vec![]],
            };
            let adapters: Vec<&dyn Adapter> = vec![ad];
            let sc = score(
                &route,
                &adapters,
                &DomainRegistry::new(),
                &Assumptions::default(),
                &MAX_DETACH,
                &SingleAsset::new("BTC", "sat"),
            )
            .expect("score");
            assert!(
                sc.joins.is_empty(),
                "{}: same-hop carried correlator must produce zero joins: {:?}",
                ad.id(),
                sc.joins
            );
            assert_eq!(
                sc.detaches,
                vec![DetachLevel::Independent],
                "{}: same-hop carried correlator is no leak",
                ad.id()
            );
        }

        // Control: a spec the adapter preserves but does NOT carry in any
        // segment is still charged.
        let plain = HopAdapter {
            id: "plain".into(),
            manifest: Manifest {
                adapter_id: "plain".into(),
                witnesses: vec![witness(
                    WitnessRole::LnPeer,
                    "ln",
                    &["ln-net"],
                    Field::TRANSACTION_ID,
                    Field::TRANSACTION_ID,
                )],
                preserves: vec![ph],
                latency_bound_secs: Some(30),
            },
            effects: SegmentEffects::default(),
            costs: vec![],
        };
        let route = Route {
            hops: vec!["plain".into()],
            states: vec![s(), s()],
            open_segments_at: vec![vec![]],
        };
        let adapters: Vec<&dyn Adapter> = vec![&plain];
        let sc = score(
            &route,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &MAX_DETACH,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect("score");
        assert_eq!(sc.joins.len(), 1, "preserved-not-carried spec is charged");
        assert_eq!(sc.joins[0].confidence, Confidence::Exact);
        assert_eq!(sc.detaches, vec![DetachLevel::None]);
    }

    #[test]
    fn declared_same_hop_segments_produce_no_carried_joins_or_leaks() {
        // The declared LightningPath and BoundedTransferStep fixtures open and
        // close their segments inside a single hop; their carried correlators
        // (lightning.payment_hash, credit.receipt_id) must produce zero
        // JoinReports and no leak.
        struct SumAll;
        impl CostPolicy for SumAll {
            fn reduce(&self, costs: &[Amount]) -> Result<f32, MoltError> {
                Ok(costs.iter().map(|c| c.value as f32).sum())
            }
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/declared");
        let ln = crate::route::DeclaredAdapter::from_file(&dir.join("lightning_path.json"))
            .expect("ln fixture");
        let bts = crate::route::DeclaredAdapter::from_file(&dir.join("bounded_transfer_step.json"))
            .expect("bts fixture");
        for (ad, kind, ns) in [
            (&ln, Field::TRANSACTION_ID, "lightning.payment_hash"),
            (&bts, Field::OBLIGATION_ID, "credit.receipt_id"),
        ] {
            let route = Route {
                hops: vec![ad.id().to_string()],
                states: vec![ad.fixture().accepts.clone(), ad.fixture().produces.clone()],
                open_segments_at: vec![vec![]],
            };
            let adapters: Vec<&dyn Adapter> = vec![ad];
            let sc = score(
                &route,
                &adapters,
                &DomainRegistry::new(),
                &Assumptions::default(),
                &MAX_DETACH,
                &SumAll,
            )
            .expect("score");
            assert!(
                sc.joins
                    .iter()
                    .all(|j| j.via.iter().all(|v| !v.kind.intersects(kind))),
                "{}: no join via the carried kind {kind:?}: {:?}",
                ad.id(),
                sc.joins
            );
            assert!(
                sc.joins
                    .iter()
                    .all(|j| j.via.iter().all(|v| v.namespace != ns)),
                "{}: no join via {ns}: {:?}",
                ad.id(),
                sc.joins
            );
        }
    }

    #[test]
    fn namespaces_distinguish_transaction_id_joins() {
        // Two hops preserving the same KIND in DIFFERENT namespaces transform
        // the value: no join spans both. Same namespace: Exact join.
        let mk = |id: &str, ns: &str| HopAdapter {
            id: id.into(),
            manifest: Manifest {
                adapter_id: id.into(),
                witnesses: vec![witness(
                    WitnessRole::Chain,
                    "c",
                    &["chain"],
                    Field::TRANSACTION_ID,
                    Field::TRANSACTION_ID,
                )],
                preserves: vec![CorrelatorSpec::new(Field::TRANSACTION_ID, ns).expect("spec")],
                latency_bound_secs: Some(1),
            },
            effects: SegmentEffects::default(),
            costs: vec![],
        };
        let run = |a1: &HopAdapter, a2: &HopAdapter| {
            let route = Route {
                hops: vec!["h1".into(), "h2".into()],
                states: vec![s(), s(), s()],
                open_segments_at: vec![vec![], vec![]],
            };
            let adapters: Vec<&dyn Adapter> = vec![a1, a2];
            score(
                &route,
                &adapters,
                &DomainRegistry::new(),
                &Assumptions::default(),
                &MAX_DETACH,
                &SingleAsset::new("BTC", "sat"),
            )
            .expect("score")
        };
        let diff = run(
            &mk("h1", "lightning.payment_hash"),
            &mk("h2", "bitcoin.txid"),
        );
        assert!(
            !diff.joins.iter().any(|j| j.joins.contains(&(0, 2))),
            "namespace change must break the cross-route join: {:?}",
            diff.joins
        );
        let same = run(
            &mk("h1", "lightning.payment_hash"),
            &mk("h2", "lightning.payment_hash"),
        );
        let full: Vec<&JoinReport> = same
            .joins
            .iter()
            .filter(|j| j.joins.contains(&(0, 2)))
            .collect();
        assert_eq!(full.len(), 1, "same namespace joins end to end");
        assert_eq!(full[0].confidence, Confidence::Exact);
        assert_eq!(full[0].via[0].namespace, "lightning.payment_hash");
    }

    #[test]
    fn amount_time_joins_only_within_window() {
        // AMOUNT/TIME joins exist only within asm.time_window_secs;
        // CONTENT_SIZE remains Statistical regardless of the window.
        let mk = |latency: u32| HopAdapter {
            id: "h".into(),
            manifest: Manifest {
                adapter_id: "h".into(),
                witnesses: vec![witness(
                    WitnessRole::Chain,
                    "c",
                    &["chain"],
                    Field::AMOUNT | Field::TIME | Field::CONTENT_SIZE,
                    Field::AMOUNT | Field::TIME | Field::CONTENT_SIZE,
                )],
                preserves: vec![
                    CorrelatorSpec::new(Field::AMOUNT, "btc.sats").expect("spec"),
                    CorrelatorSpec::new(Field::TIME, "time.unix").expect("spec"),
                    CorrelatorSpec::new(Field::CONTENT_SIZE, "wire.bytes").expect("spec"),
                ],
                latency_bound_secs: Some(latency),
            },
            effects: SegmentEffects::default(),
            costs: vec![],
        };
        let run = |ad: &HopAdapter| {
            let route = Route {
                hops: vec!["h".into()],
                states: vec![s(), s()],
                open_segments_at: vec![vec![]],
            };
            let adapters: Vec<&dyn Adapter> = vec![ad];
            score(
                &route,
                &adapters,
                &DomainRegistry::new(),
                &Assumptions::default(), // window 3600
                &MAX_DETACH,
                &SingleAsset::new("BTC", "sat"),
            )
            .expect("score")
        };
        let far = run(&mk(7200));
        assert!(
            !far.joins.iter().any(|j| j
                .via
                .iter()
                .any(|v| v.kind.intersects(Field::AMOUNT | Field::TIME))),
            "outside the window AMOUNT/TIME produce no join: {:?}",
            far.joins
        );
        let cs = far
            .joins
            .iter()
            .find(|j| j.via.iter().any(|v| v.kind.contains(Field::CONTENT_SIZE)))
            .expect("CONTENT_SIZE join remains regardless of window");
        assert_eq!(cs.confidence, Confidence::Statistical);

        let near = run(&mk(60));
        let amt = near
            .joins
            .iter()
            .find(|j| j.via.iter().any(|v| v.kind.contains(Field::AMOUNT)))
            .expect("AMOUNT join within the window");
        assert_eq!(amt.confidence, Confidence::High);
    }

    #[test]
    fn invalid_weights_rejected() {
        let (route, ad) = one_hop(Manifest {
            adapter_id: "h".into(),
            witnesses: vec![],
            preserves: vec![],
            latency_bound_secs: None,
        });
        let adapters: Vec<&dyn Adapter> = vec![&ad];
        let bad = Weights {
            continuity: f32::NAN,
            cost: 0.0,
            latency: 0.0,
        };
        assert!(score(
            &route,
            &adapters,
            &DomainRegistry::new(),
            &Assumptions::default(),
            &bad,
            &SingleAsset::new("BTC", "sat")
        )
        .is_err());
    }

    #[test]
    fn colluding_pair_join_reported_with_set_weight() {
        // d1 sees AMOUNT at point 0; d2 sees AMOUNT at point 1. Only the pair
        // {d1, d2} joins; with k=1 no join is reported, with k=2 it is.
        let m = Manifest {
            adapter_id: "h".into(),
            witnesses: vec![
                witness(
                    WitnessRole::RelayOperator,
                    "r1",
                    &["d1"],
                    Field::AMOUNT,
                    Field::empty(),
                ),
                witness(
                    WitnessRole::Homeserver,
                    "h1",
                    &["d2"],
                    Field::empty(),
                    Field::AMOUNT,
                ),
            ],
            preserves: vec![CorrelatorSpec::new(Field::AMOUNT, "btc.sats").expect("spec")],
            latency_bound_secs: Some(1),
        };
        let (route, ad) = one_hop(m);
        let adapters: Vec<&dyn Adapter> = vec![&ad];
        let asm1 = Assumptions {
            colluding_set_size: 1,
            ..Assumptions::default()
        };
        let s1 = score(
            &route,
            &adapters,
            &DomainRegistry::new(),
            &asm1,
            &MAX_DETACH,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect("score");
        assert!(s1.joins.is_empty());
        let asm2 = Assumptions {
            colluding_set_size: 2,
            ..Assumptions::default()
        };
        let s2 = score(
            &route,
            &adapters,
            &DomainRegistry::new(),
            &asm2,
            &MAX_DETACH,
            &SingleAsset::new("BTC", "sat"),
        )
        .expect("score");
        assert_eq!(s2.joins.len(), 1);
        assert_eq!(s2.joins[0].domain_set.len(), 2);
        assert_eq!(s2.joins[0].confidence, Confidence::High);
    }
}
