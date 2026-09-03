//! S6. Bounded BFS planner.
//!
//! Extends only from [`Holder::Self_`]-held states. Rejects: routes that
//! leave a segment open at the end; a `closes` with no matching open segment;
//! a duplicate [`SegmentId`]; any boundary returning
//! [`SegmentViolation`]; any violated [`RouteConstraint`]; any `Custom`
//! constraint with no registered evaluator (fail closed). No cycles.
//! Rejections are returned, not silently dropped, so callers can see why.

use crate::route::{Adapter, ConstraintEvaluators, Holder, Route, RouteConstraint, RouteState};
use crate::witness::{
    detach_level, Assumptions, DomainRegistry, Segment, SegmentId, SegmentViolation,
};
use crate::PurposeId;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Hard bounds on the search. v1 defaults: depth 4, at most 8 routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerLimits {
    /// Maximum number of hops in a route (v1: 4).
    pub max_depth: u8,
    /// Maximum number of complete routes returned (v1: 8).
    pub max_routes: u8,
}

impl Default for PlannerLimits {
    fn default() -> Self {
        PlannerLimits {
            max_depth: 4,
            max_routes: 8,
        }
    }
}

/// Why a (partial) route was rejected.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RejectReason {
    /// The route reached a state not held by `Self` that is not the goal;
    /// the planner only extends from `Self`-held states.
    HolderNotSelf,
    /// The route ended with this segment still open.
    UnclosedSegment(SegmentId),
    /// A hop closed (or continued) a segment that was not open.
    CloseWithoutOpen(SegmentId),
    /// A hop opened a segment id already used on this route.
    DuplicateSegmentId(SegmentId),
    /// A boundary violated a segment's continuity requirement.
    Segment(SegmentViolation),
    /// A route constraint was violated.
    Constraint(RouteConstraint),
    /// FAIL CLOSED: an adapter declared a `Custom` constraint whose
    /// namespace has no registered evaluator.
    UnsupportedConstraint {
        /// The unregistered namespace.
        namespace: PurposeId,
        /// The adapter declaring the constraint.
        adapter: String,
    },
    /// The route reached `max_depth` without reaching the goal.
    DepthExceeded,
}

/// The planner's output: complete routes plus every rejected partial route
/// with its reason.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PlanResult {
    /// Complete routes from `from` to `to`, in BFS discovery order.
    pub routes: Vec<Route>,
    /// Rejected partial routes with their reasons.
    pub rejected: Vec<(Route, RejectReason)>,
}

/// Find an adapter by id.
fn by_id<'a>(adapters: &[&'a dyn Adapter], id: &str) -> Option<&'a dyn Adapter> {
    adapters.iter().find(|a| a.id() == id).copied()
}

/// Check constraints of the previous hop that can only be evaluated once its
/// successor is known (`RequiresSuccessor`, the successor side of
/// `ExclusiveAdjacency`).
fn check_prev_deferred(r: &Route, new_id: &str, adapters: &[&dyn Adapter]) -> Option<RejectReason> {
    let prev_id = r.hops.last()?;
    let prev = by_id(adapters, prev_id)?;
    for c in prev.route_constraints() {
        match c {
            RouteConstraint::RequiresSuccessor(s) => {
                if s != new_id {
                    return Some(RejectReason::Constraint(c.clone()));
                }
            }
            RouteConstraint::ExclusiveAdjacency(x) => {
                let n = r.hops.len();
                let pred_ok = n >= 2 && &r.hops[n - 2] == x;
                if !pred_ok && x != new_id {
                    return Some(RejectReason::Constraint(c.clone()));
                }
            }
            _ => {}
        }
    }
    None
}

/// Check trailing constraints when a route ends (`RequiresSuccessor` and
/// `ExclusiveAdjacency` must be satisfied by the predecessor, since there is
/// no successor).
fn check_trailing(r: &Route, adapters: &[&dyn Adapter]) -> Option<RejectReason> {
    let last_id = r.hops.last()?;
    let last = by_id(adapters, last_id)?;
    for c in last.route_constraints() {
        match c {
            RouteConstraint::RequiresSuccessor(_) => {
                return Some(RejectReason::Constraint(c.clone()))
            }
            RouteConstraint::ExclusiveAdjacency(x) => {
                let n = r.hops.len();
                if n < 2 || &r.hops[n - 2] != x {
                    return Some(RejectReason::Constraint(c.clone()));
                }
            }
            _ => {}
        }
    }
    None
}

/// Attempt to extend route `r` with adapter `ad`, producing `next`.
/// On success returns the extended route; on failure the rejection reason.
fn try_extend(
    r: &Route,
    ad: &dyn Adapter,
    next: &RouteState,
    adapters: &[&dyn Adapter],
    evals: &ConstraintEvaluators,
) -> Result<Route, RejectReason> {
    let effects = ad.segments();

    // --- Segment bookkeeping ---
    let mut open: Vec<Segment> = r.open_segments().to_vec();
    // Boundary check: segments open across the boundary between the previous
    // hop and this one must have their carries preserved by the previous hop.
    if !open.is_empty() {
        if let Some(prev_id) = r.hops.last() {
            if let Some(prev) = by_id(adapters, prev_id) {
                let reg = DomainRegistry::new();
                let asm = Assumptions::default();
                if let Err(v) = detach_level(&prev.manifest(), &ad.manifest(), &open, &reg, &asm) {
                    return Err(RejectReason::Segment(v));
                }
            }
        }
    }
    // Effects apply opens → continues → closes within the hop, so an adapter
    // may open and close the same segment in one hop (a Lightning path opens
    // and closes its payment-hash segment in a single adapter).
    let before = open.clone();
    for seg in &effects.opens {
        let already_open = before.iter().any(|s| s.id == seg.id);
        let used_before = r.open_segments_at.iter().flatten().any(|s| s.id == seg.id);
        if already_open || used_before {
            return Err(RejectReason::DuplicateSegmentId(seg.id.clone()));
        }
        open.push(seg.clone());
    }
    for id in &effects.continues {
        // Continuing a segment that is not open is the same class of
        // bookkeeping error as closing one (see DECISIONS.md).
        if !open.iter().any(|s| &s.id == id) {
            return Err(RejectReason::CloseWithoutOpen(id.clone()));
        }
    }
    for id in &effects.closes {
        match open.iter().position(|s| &s.id == id) {
            Some(i) => {
                open.remove(i);
            }
            None => return Err(RejectReason::CloseWithoutOpen(id.clone())),
        }
    }

    // --- Constraint checks ---
    if let Some(reason) = check_prev_deferred(r, ad.id(), adapters) {
        return Err(reason);
    }
    let at_hop = r.hops.len();
    let candidate = Route {
        hops: r
            .hops
            .iter()
            .cloned()
            .chain(std::iter::once(ad.id().to_string()))
            .collect(),
        states: r
            .states
            .iter()
            .cloned()
            .chain(std::iter::once(next.clone()))
            .collect(),
        open_segments_at: r
            .open_segments_at
            .iter()
            .cloned()
            .chain(std::iter::once(open))
            .collect(),
    };
    for c in ad.route_constraints() {
        match c {
            RouteConstraint::NotRepeatable => {
                if r.hops.iter().any(|h| h == ad.id()) {
                    return Err(RejectReason::Constraint(c.clone()));
                }
            }
            RouteConstraint::RequiresPredecessor(p) => {
                if r.hops.last() != Some(p) {
                    return Err(RejectReason::Constraint(c.clone()));
                }
            }
            RouteConstraint::RequiresSuccessor(_) | RouteConstraint::ExclusiveAdjacency(_) => {
                // Deferred: evaluated when the successor is added, or at
                // finalization if this hop is last.
            }
            RouteConstraint::Custom { namespace, rule } => match evals.get(namespace) {
                None => {
                    return Err(RejectReason::UnsupportedConstraint {
                        namespace: namespace.clone(),
                        adapter: ad.id().to_string(),
                    })
                }
                Some(ev) => {
                    if !ev.holds(rule, &candidate, at_hop) {
                        return Err(RejectReason::Constraint(c.clone()));
                    }
                }
            },
        }
    }
    Ok(candidate)
}

/// Finalize a route whose current state equals the goal. On rejection the
/// route is returned alongside the reason so callers can inspect it.
fn finalize(r: Route, adapters: &[&dyn Adapter]) -> Result<Route, Box<(Route, RejectReason)>> {
    if let Some(seg) = r.open_segments().first() {
        let reason = RejectReason::UnclosedSegment(seg.id.clone());
        return Err(Box::new((r, reason)));
    }
    if let Some(reason) = check_trailing(&r, adapters) {
        return Err(Box::new((r, reason)));
    }
    Ok(r)
}

/// Bounded BFS from `from` to `to` over `adapters`.
///
/// Extends only from [`Holder::Self_`]-held states. A produced state equal to
/// `to` is accepted regardless of holder (a payment ends at the receiver).
/// No state is visited twice within a route (no cycles). At most
/// `lim.max_depth` hops and `lim.max_routes` complete routes.
pub fn plan(
    from: &RouteState,
    to: &RouteState,
    adapters: &[&dyn Adapter],
    evals: &ConstraintEvaluators,
    lim: &PlannerLimits,
) -> PlanResult {
    let mut result = PlanResult::default();
    if from == to {
        result.routes.push(Route::start(from));
        return result;
    }
    let mut queue: VecDeque<Route> = VecDeque::new();
    queue.push_back(Route::start(from));
    while let Some(r) = queue.pop_front() {
        if result.routes.len() >= lim.max_routes as usize {
            break;
        }
        let cur = r.current().clone();
        if &cur == to {
            match finalize(r, adapters) {
                Ok(done) => result.routes.push(done),
                Err(rej) => result.rejected.push((rej.0, rej.1)),
            }
            continue;
        }
        if cur.holder() != Holder::Self_ {
            result.rejected.push((r, RejectReason::HolderNotSelf));
            continue;
        }
        if r.hops.len() >= lim.max_depth as usize {
            result.rejected.push((r, RejectReason::DepthExceeded));
            continue;
        }
        for ad in adapters {
            let ad: &dyn Adapter = *ad;
            if !ad.accepts(&cur) {
                continue;
            }
            let Some(next) = ad.produces(&cur) else {
                continue;
            };
            if r.states.contains(&next) {
                continue; // no cycles
            }
            match try_extend(&r, ad, &next, adapters, evals) {
                Ok(candidate) => queue.push_back(candidate),
                Err(reason) => {
                    let partial = attempted_stub(&r, ad, &next);
                    result.rejected.push((partial, reason));
                }
            }
        }
    }
    result
}

/// The partial route recording a failed extension attempt (includes the
/// attempted hop and produced state for diagnosability).
fn attempted_stub(r: &Route, ad: &dyn Adapter, next: &RouteState) -> Route {
    Route {
        hops: r
            .hops
            .iter()
            .cloned()
            .chain(std::iter::once(ad.id().to_string()))
            .collect(),
        states: r
            .states
            .iter()
            .cloned()
            .chain(std::iter::once(next.clone()))
            .collect(),
        open_segments_at: r.open_segments_at.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::{Amount, ConstraintEvaluator, Quote, RecoverySemantics};
    use crate::witness::{CorrelatorSpec, Field, Manifest, SegmentEffects};
    use serde_json::json;

    fn value(net: &str, holder: Holder) -> RouteState {
        RouteState::Value {
            network: net.into(),
            amount: None,
            holder,
        }
    }

    /// Hand-rolled test adapter (multi-state, arbitrary constraints), as
    /// opposed to `DeclaredAdapter` which matches one template.
    struct TestAdapter {
        id: String,
        from: Vec<RouteState>,
        to: RouteState,
        manifest: Manifest,
        effects: SegmentEffects,
        constraints: Vec<RouteConstraint>,
    }

    impl TestAdapter {
        fn new(id: &str, from: Vec<RouteState>, to: RouteState) -> Self {
            TestAdapter {
                id: id.into(),
                from,
                to,
                manifest: Manifest {
                    adapter_id: id.into(),
                    witnesses: vec![],
                    preserves: vec![],
                    latency_bound_secs: Some(10),
                },
                effects: SegmentEffects::default(),
                constraints: vec![],
            }
        }
    }

    impl Adapter for TestAdapter {
        fn id(&self) -> &str {
            &self.id
        }
        fn accepts(&self, s: &RouteState) -> bool {
            self.from.contains(s)
        }
        fn produces(&self, s: &RouteState) -> Option<RouteState> {
            if self.accepts(s) {
                Some(self.to.clone())
            } else {
                None
            }
        }
        fn manifest(&self) -> Manifest {
            self.manifest.clone()
        }
        fn quote(&self, _s: &RouteState) -> Quote {
            Quote {
                costs: vec![],
                latency_secs: 10,
            }
        }
        fn recovery(&self) -> RecoverySemantics {
            RecoverySemantics::Atomic
        }
        fn segments(&self) -> SegmentEffects {
            self.effects.clone()
        }
        fn route_constraints(&self) -> &[RouteConstraint] {
            &self.constraints
        }
    }

    fn no_evals() -> ConstraintEvaluators {
        ConstraintEvaluators::new()
    }

    fn v1() -> PlannerLimits {
        PlannerLimits::default()
    }

    #[test]
    fn trivial_route_when_from_equals_to() {
        let s = value("bitcoin", Holder::Self_);
        let res = plan(&s, &s, &[], &no_evals(), &v1());
        assert_eq!(res.routes.len(), 1);
        assert!(res.routes[0].hops.is_empty());
        assert!(res.rejected.is_empty());
    }

    #[test]
    fn refuses_counterparty_held_extension_but_accepts_as_goal() {
        // BoundedTransferStep-shape: Self -> Counterparty.
        let a = TestAdapter::new(
            "bts",
            vec![value("credit-line", Holder::Self_)],
            value("credit-line", Holder::Counterparty),
        );
        let b = TestAdapter::new(
            "after",
            vec![value("credit-line", Holder::Counterparty)],
            value("other", Holder::Self_),
        );
        let adapters: Vec<&dyn Adapter> = vec![&a, &b];
        let from = value("credit-line", Holder::Self_);
        // Goal is the Counterparty-held state: accepted (payment ends at receiver).
        let res = plan(
            &from,
            &value("credit-line", Holder::Counterparty),
            &adapters,
            &no_evals(),
            &v1(),
        );
        assert_eq!(res.routes.len(), 1);
        assert_eq!(res.routes[0].hops, vec!["bts"]);
        // Goal beyond the Counterparty-held state: refused with HolderNotSelf.
        let res2 = plan(
            &from,
            &value("other", Holder::Self_),
            &adapters,
            &no_evals(),
            &v1(),
        );
        assert!(res2.routes.is_empty());
        assert!(res2
            .rejected
            .iter()
            .any(|(_, r)| matches!(r, RejectReason::HolderNotSelf)));
    }

    #[test]
    fn rejects_unclosed_segment_and_close_without_open_and_duplicate_id() {
        let seg = Segment {
            id: SegmentId("s1".into()),
            carries: vec![CorrelatorSpec::new(Field::TRANSACTION_ID, "swap.hash").expect("spec")],
        };
        let mut opener = TestAdapter::new(
            "opener",
            vec![value("a", Holder::Self_)],
            value("b", Holder::Self_),
        );
        opener.effects.opens = vec![seg.clone()];
        opener.manifest.preserves =
            vec![CorrelatorSpec::new(Field::TRANSACTION_ID, "swap.hash").expect("spec")];
        let adapters: Vec<&dyn Adapter> = vec![&opener];
        let res = plan(
            &value("a", Holder::Self_),
            &value("b", Holder::Self_),
            &adapters,
            &no_evals(),
            &v1(),
        );
        assert!(res.routes.is_empty());
        assert!(res
            .rejected
            .iter()
            .any(|(_, r)| matches!(r, RejectReason::UnclosedSegment(id) if id.0 == "s1")));

        // close without open
        let mut closer = TestAdapter::new(
            "closer",
            vec![value("a", Holder::Self_)],
            value("b", Holder::Self_),
        );
        closer.effects.closes = vec![SegmentId("nope".into())];
        let adapters2: Vec<&dyn Adapter> = vec![&closer];
        let res2 = plan(
            &value("a", Holder::Self_),
            &value("b", Holder::Self_),
            &adapters2,
            &no_evals(),
            &v1(),
        );
        assert!(res2
            .rejected
            .iter()
            .any(|(_, r)| matches!(r, RejectReason::CloseWithoutOpen(id) if id.0 == "nope")));

        // duplicate id: opener -> opener2 both open "s1"
        let mut opener2 = TestAdapter::new(
            "opener2",
            vec![value("b", Holder::Self_)],
            value("c", Holder::Self_),
        );
        opener2.effects.opens = vec![seg];
        let adapters3: Vec<&dyn Adapter> = vec![&opener, &opener2];
        let res3 = plan(
            &value("a", Holder::Self_),
            &value("c", Holder::Self_),
            &adapters3,
            &no_evals(),
            &v1(),
        );
        assert!(res3.routes.is_empty());
        assert!(res3
            .rejected
            .iter()
            .any(|(_, r)| matches!(r, RejectReason::DuplicateSegmentId(id) if id.0 == "s1")));
    }

    #[test]
    fn rejects_boundary_segment_violation() {
        // opener opens a segment but does NOT preserve its carries; any
        // following hop crosses a violating boundary.
        let seg = Segment {
            id: SegmentId("seg".into()),
            carries: vec![CorrelatorSpec::new(Field::TRANSACTION_ID, "swap.hash").expect("spec")],
        };
        let mut opener = TestAdapter::new(
            "opener",
            vec![value("a", Holder::Self_)],
            value("b", Holder::Self_),
        );
        opener.effects.opens = vec![seg];
        let mut cont = TestAdapter::new(
            "cont",
            vec![value("b", Holder::Self_)],
            value("c", Holder::Self_),
        );
        cont.effects.continues = vec![SegmentId("seg".into())];
        cont.effects.closes = vec![SegmentId("seg".into())];
        let adapters: Vec<&dyn Adapter> = vec![&opener, &cont];
        let res = plan(
            &value("a", Holder::Self_),
            &value("c", Holder::Self_),
            &adapters,
            &no_evals(),
            &v1(),
        );
        assert!(res.routes.is_empty());
        assert!(res
            .rejected
            .iter()
            .any(|(_, r)| matches!(r, RejectReason::Segment(v) if v.segment.0 == "seg")));
    }

    #[test]
    fn accepts_submarine_swap_then_lightning_path() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/declared");
        let swap = crate::route::DeclaredAdapter::from_file(&dir.join("submarine_swap.json"))
            .expect("swap fixture");
        let ln = crate::route::DeclaredAdapter::from_file(&dir.join("lightning_path.json"))
            .expect("ln fixture");
        let adapters: Vec<&dyn Adapter> = vec![&swap, &ln];
        let from = swap.fixture().accepts.clone();
        let to = ln.fixture().produces.clone();
        let res = plan(&from, &to, &adapters, &no_evals(), &v1());
        assert_eq!(res.routes.len(), 1, "rejected: {:?}", res.rejected);
        assert_eq!(
            res.routes[0].hops,
            vec![
                "molt.declared.submarine_swap",
                "molt.declared.lightning_path"
            ]
        );
        // Swap output is Self-held, so the route composes; the LN payment hash
        // segment opens and closes inside the lightning hop.
        assert!(res.routes[0].open_segments().is_empty());
    }

    #[test]
    fn enforces_not_repeatable() {
        let mut nr = TestAdapter::new(
            "nr",
            vec![value("a", Holder::Self_), value("b", Holder::Self_)],
            value("b", Holder::Self_),
        );
        nr.constraints = vec![RouteConstraint::NotRepeatable];
        // To reach "b" from "a" uses nr once: fine.
        let adapters: Vec<&dyn Adapter> = vec![&nr];
        let res = plan(
            &value("a", Holder::Self_),
            &value("b", Holder::Self_),
            &adapters,
            &no_evals(),
            &v1(),
        );
        assert_eq!(res.routes.len(), 1);

        // Force a second use: nr2 same adapter id path a->b, b->c requires "nr" again.
        let mut nr2 = TestAdapter::new(
            "nr",
            vec![value("b", Holder::Self_)],
            value("c", Holder::Self_),
        );
        nr2.constraints = vec![RouteConstraint::NotRepeatable];
        let adapters2: Vec<&dyn Adapter> = vec![&nr, &nr2];
        let res2 = plan(
            &value("a", Holder::Self_),
            &value("c", Holder::Self_),
            &adapters2,
            &no_evals(),
            &v1(),
        );
        assert!(res2.routes.is_empty());
        assert!(res2
            .rejected
            .iter()
            .any(|(_, r)| matches!(r, RejectReason::Constraint(RouteConstraint::NotRepeatable))));
    }

    #[test]
    fn enforces_exclusive_adjacency_and_requires_successor() {
        let s0 = value("s0", Holder::Self_);
        let s1 = value("s1", Holder::Self_);
        let s2 = value("s2", Holder::Self_);
        let s3 = value("s3", Holder::Self_);
        let mut a = TestAdapter::new("a", vec![s0.clone()], s1.clone());
        a.constraints = vec![RouteConstraint::ExclusiveAdjacency("b".into())];
        let b = TestAdapter::new("b", vec![s1.clone()], s2.clone());
        let c = TestAdapter::new("c", vec![s1.clone()], s3.clone());

        // a adjacent to b: accepted.
        let adapters: Vec<&dyn Adapter> = vec![&a, &b, &c];
        let res = plan(&s0, &s2, &adapters, &no_evals(), &v1());
        assert_eq!(res.routes.len(), 1, "rejected: {:?}", res.rejected);
        assert_eq!(res.routes[0].hops, vec!["a", "b"]);

        // a adjacent to c: rejected when c is appended after a.
        let res2 = plan(&s0, &s3, &adapters, &no_evals(), &v1());
        assert!(res2.routes.is_empty());
        assert!(res2.rejected.iter().any(|(_, r)| matches!(r, RejectReason::Constraint(RouteConstraint::ExclusiveAdjacency(x)) if x == "b")));

        // a as the final hop (goal s1): rejected (no successor, predecessor not "b").
        let res3 = plan(&s0, &s1, &adapters, &no_evals(), &v1());
        assert!(res3.routes.is_empty());
        assert!(res3.rejected.iter().any(|(_, r)| matches!(r, RejectReason::Constraint(RouteConstraint::ExclusiveAdjacency(x)) if x == "b")));

        // RequiresSuccessor: a2 must be followed by b.
        let mut a2 = TestAdapter::new("a2", vec![s0.clone()], s1.clone());
        a2.constraints = vec![RouteConstraint::RequiresSuccessor("b".into())];
        let adapters2: Vec<&dyn Adapter> = vec![&a2, &b, &c];
        let res4 = plan(&s0, &s2, &adapters2, &no_evals(), &v1());
        assert_eq!(res4.routes.len(), 1);
        let res5 = plan(&s0, &s1, &adapters2, &no_evals(), &v1());
        assert!(res5.routes.is_empty());
        assert!(res5.rejected.iter().any(|(_, r)| matches!(r, RejectReason::Constraint(RouteConstraint::RequiresSuccessor(x)) if x == "b")));
    }

    #[test]
    fn enforces_requires_predecessor() {
        let s0 = value("s0", Holder::Self_);
        let s1 = value("s1", Holder::Self_);
        let s2 = value("s2", Holder::Self_);
        let a = TestAdapter::new("a", vec![s0.clone()], s1.clone());
        let mut b = TestAdapter::new("b", vec![s0.clone(), s1.clone()], s2.clone());
        b.constraints = vec![RouteConstraint::RequiresPredecessor("a".into())];
        let adapters: Vec<&dyn Adapter> = vec![&a, &b];
        let res = plan(&s0, &s2, &adapters, &no_evals(), &v1());
        assert_eq!(res.routes.len(), 1);
        assert_eq!(res.routes[0].hops, vec!["a", "b"]);
        // b directly from s0: rejected.
        let res2 = plan(&s0, &s2, &[&b as &dyn Adapter], &no_evals(), &v1());
        assert!(res2.routes.is_empty());
        assert!(res2.rejected.iter().any(|(_, r)| matches!(r, RejectReason::Constraint(RouteConstraint::RequiresPredecessor(x)) if x == "a")));
    }

    #[test]
    fn routes_through_custom_state() {
        let ns = PurposeId::parse("pubky.molt.rendezvous.v1").expect("pid");
        let s0 = value("s0", Holder::Self_);
        let custom = RouteState::Custom {
            namespace: ns.clone(),
            descriptor: json!({"slot": 3}),
            holder: Holder::Self_,
        };
        let s2 = value("s2", Holder::Self_);
        let c1 = TestAdapter::new("c1", vec![s0.clone()], custom.clone());
        let c2 = TestAdapter::new("c2", vec![custom.clone()], s2.clone());
        let adapters: Vec<&dyn Adapter> = vec![&c1, &c2];
        let res = plan(&s0, &s2, &adapters, &no_evals(), &v1());
        assert_eq!(res.routes.len(), 1, "rejected: {:?}", res.rejected);
        assert_eq!(res.routes[0].hops, vec!["c1", "c2"]);
        assert_eq!(res.routes[0].states[1], custom);
    }

    struct FlagEval(PurposeId, bool);
    impl ConstraintEvaluator for FlagEval {
        fn namespace(&self) -> &PurposeId {
            &self.0
        }
        fn holds(&self, _rule: &serde_json::Value, _route: &Route, _at_hop: usize) -> bool {
            self.1
        }
    }

    #[test]
    fn custom_constraint_fails_closed_then_uses_evaluator() {
        let ns = PurposeId::parse("pubky.molt.policy.v1").expect("pid");
        let s0 = value("s0", Holder::Self_);
        let s1 = value("s1", Holder::Self_);
        let mut ad = TestAdapter::new("guarded", vec![s0.clone()], s1.clone());
        ad.constraints = vec![RouteConstraint::Custom {
            namespace: ns.clone(),
            rule: json!({"min": 1}),
        }];
        let adapters: Vec<&dyn Adapter> = vec![&ad];

        // No evaluator registered: fail closed with UnsupportedConstraint.
        let res = plan(&s0, &s1, &adapters, &no_evals(), &v1());
        assert!(res.routes.is_empty());
        assert!(res.rejected.iter().any(|(_, r)| matches!(
            r,
            RejectReason::UnsupportedConstraint { namespace, adapter } if namespace == &ns && adapter == "guarded"
        )));

        // Evaluator registered and holding: accepted.
        let mut evals = ConstraintEvaluators::new();
        evals.register(Box::new(FlagEval(ns.clone(), true)));
        let res2 = plan(&s0, &s1, &adapters, &evals, &v1());
        assert_eq!(res2.routes.len(), 1);

        // Evaluator registered and not holding: rejected as Constraint.
        let mut evals2 = ConstraintEvaluators::new();
        evals2.register(Box::new(FlagEval(ns, false)));
        let res3 = plan(&s0, &s1, &adapters, &evals2, &v1());
        assert!(res3.routes.is_empty());
        assert!(res3
            .rejected
            .iter()
            .any(|(_, r)| matches!(r, RejectReason::Constraint(RouteConstraint::Custom { .. }))));
    }

    #[test]
    fn depth_limit_is_enforced() {
        let s0 = value("s0", Holder::Self_);
        let s1 = value("s1", Holder::Self_);
        let s2 = value("s2", Holder::Self_);
        let a = TestAdapter::new("a", vec![s0.clone()], s1.clone());
        let b = TestAdapter::new("b", vec![s1.clone()], s2.clone());
        let adapters: Vec<&dyn Adapter> = vec![&a, &b];
        let lim = PlannerLimits {
            max_depth: 1,
            max_routes: 8,
        };
        let res = plan(&s0, &s2, &adapters, &no_evals(), &lim);
        assert!(res.routes.is_empty());
        assert!(res
            .rejected
            .iter()
            .any(|(_, r)| matches!(r, RejectReason::DepthExceeded)));
        let res2 = plan(&s0, &s2, &adapters, &no_evals(), &v1());
        assert_eq!(res2.routes.len(), 1);
    }

    #[test]
    fn no_cycles_and_max_routes_bound() {
        // a: s0<->s1 ping-pong adapters; cycle must not appear.
        let s0 = value("s0", Holder::Self_);
        let s1 = value("s1", Holder::Self_);
        let a = TestAdapter::new("a", vec![s0.clone()], s1.clone());
        let b = TestAdapter::new("b", vec![s1.clone()], s0.clone());
        let adapters: Vec<&dyn Adapter> = vec![&a, &b];
        let res = plan(&s0, &s1, &adapters, &no_evals(), &v1());
        assert_eq!(res.routes.len(), 1);
        assert_eq!(res.routes[0].hops, vec!["a"]);
    }

    #[test]
    fn amount_carrying_states_plan() {
        let amt = |v| {
            Some(Amount {
                asset: "BTC".into(),
                units: "sat".into(),
                value: v,
            })
        };
        let s0 = RouteState::Value {
            network: "bitcoin".into(),
            amount: amt(100_000),
            holder: Holder::Self_,
        };
        let s1 = RouteState::Value {
            network: "lightning".into(),
            amount: amt(100_000),
            holder: Holder::Self_,
        };
        let a = TestAdapter::new("swap", vec![s0.clone()], s1.clone());
        let adapters: Vec<&dyn Adapter> = vec![&a];
        let res = plan(&s0, &s1, &adapters, &no_evals(), &v1());
        assert_eq!(res.routes.len(), 1);
    }
}
