//! S6. Route graph: states, adapters, constraints (fail-closed), routes.
//!
//! Three protocol-neutral facts govern composition: **who holds the state**
//! ([`Holder`]), **which segments are open** ([`crate::witness::Segment`]),
//! and an **extensible constraint escape hatch** ([`RouteConstraint`]) that
//! is empty for every v1 adapter. `Holder` does most of the work; it is not
//! claimed to do all of it.

use crate::witness::{Manifest, Segment, SegmentEffects};
use crate::{MoltError, PurposeId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identity scope of a [`RouteState::Identity`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityScope {
    /// The public, stable, linkable-on-purpose root.
    Root,
    /// A pairwise (bond-scoped) identity.
    Pairwise,
    /// A session-scoped identity.
    Session,
    /// No identity presented.
    Anonymous,
}

/// Who controls a [`RouteState`]. The planner extends a route only from
/// states held by [`Holder::Self_`]. This is what ends a route when control
/// passes: a payment ends at the receiver; a bounded transfer through an
/// intermediary leaves the payee holding a claim; a swap claim leaves `Self`
/// holding the output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Holder {
    /// The principal running the planner.
    Self_,
    /// The protocol counterparty.
    Counterparty,
    /// An intermediary.
    Intermediary,
}

/// Asset-neutral quantity. Molt never assumes sats, never converts, never
/// sums across assets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Amount {
    /// Asset class, e.g. `"BTC"`, `"USD"`, `"USDT"`, `"bandwidth"`.
    pub asset: String,
    /// Unit of account, e.g. `"sat"`, `"cent"`, `"byte"`.
    pub units: String,
    /// Quantity in `units`.
    pub value: u128,
}

/// The typed position of an interaction: identity scope, transport, or
/// asset/network.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RouteState {
    /// An identity-scope position.
    Identity {
        /// Which identity scope is presented.
        scope: IdentityScope,
        /// Who controls this state.
        holder: Holder,
    },
    /// A transport position.
    Transport {
        /// Transport network name (e.g. `"drop"`, `"pubky-storage"`).
        network: String,
        /// What kind of endpoint is exposed (e.g. `"opaque-channel"`).
        endpoint_kind: String,
        /// Who controls this state.
        holder: Holder,
    },
    /// A value position on some network.
    Value {
        /// Value network name (e.g. `"bitcoin"`, `"lightning"`, `"credit-line"`).
        network: String,
        /// The amount in flight, if the adapter declares one.
        amount: Option<Amount>,
        /// Who controls this state.
        holder: Holder,
    },
    /// Application-defined state (data availability, compute, storage,
    /// capability, service access, rendezvous, ...). `namespace` follows the
    /// [`PurposeId`] grammar; `descriptor` is opaque to Molt and compared
    /// structurally by the owning adapter.
    Custom {
        /// Application namespace owning this state.
        namespace: PurposeId,
        /// Opaque application descriptor.
        descriptor: serde_json::Value,
        /// Who controls this state.
        holder: Holder,
    },
}

impl RouteState {
    /// Who holds this state.
    pub fn holder(&self) -> Holder {
        match self {
            RouteState::Identity { holder, .. }
            | RouteState::Transport { holder, .. }
            | RouteState::Value { holder, .. }
            | RouteState::Custom { holder, .. } => *holder,
        }
    }
}

/// Heterogeneous costs of one hop. Reduction to one preference number is
/// caller policy (see [`crate::score::CostPolicy`]), never Molt's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quote {
    /// All costs of the hop, each in its own asset.
    pub costs: Vec<Amount>,
    /// Declared hop latency.
    pub latency_secs: u32,
}

/// What happens if a hop fails mid-route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoverySemantics {
    /// Retrying the hop is safe.
    Idempotent,
    /// Funds are recoverable within a time window.
    Refundable {
        /// Refund window.
        window_secs: u32,
    },
    /// The hop either completes fully or not at all.
    Atomic,
    /// Failure exposes a bounded number of legs attributable to the principal.
    BoundedAttributable {
        /// Maximum legs exposed on failure.
        max_exposed_legs: u8,
    },
    /// No recovery guarantee.
    BestEffort,
}

/// Route-wide constraints beyond [`Holder`]/[`crate::witness::Segment`].
/// Every v1 adapter returns an empty slice.
///
/// FAIL CLOSED: a constraint the planner cannot evaluate makes the route
/// ineligible. [`RouteConstraint::Custom`] is evaluated only if an evaluator
/// for its namespace is registered in [`ConstraintEvaluators`]; otherwise the
/// route is rejected with
/// [`crate::planner::RejectReason::UnsupportedConstraint`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RouteConstraint {
    /// At most once per route.
    NotRepeatable,
    /// The previous hop must be the named adapter.
    RequiresPredecessor(String),
    /// The next hop must be the named adapter.
    RequiresSuccessor(String),
    /// Must be directly adjacent (predecessor or successor) to the named adapter.
    ExclusiveAdjacency(String),
    /// Application-defined rule, evaluated by a registered
    /// [`ConstraintEvaluator`] for `namespace`.
    Custom {
        /// Application namespace owning this rule.
        namespace: PurposeId,
        /// Opaque rule, interpreted by the evaluator.
        rule: serde_json::Value,
    },
}

/// Evaluates [`RouteConstraint::Custom`] rules for one namespace.
pub trait ConstraintEvaluator: Send + Sync {
    /// The namespace this evaluator is registered for.
    fn namespace(&self) -> &PurposeId;
    /// Whether `rule` holds for `route` at hop index `at_hop`.
    fn holds(&self, rule: &serde_json::Value, route: &Route, at_hop: usize) -> bool;
}

/// Registry of [`ConstraintEvaluator`]s by namespace. Empty in v1; a
/// [`RouteConstraint::Custom`] with no registered evaluator fails closed.
#[derive(Default)]
pub struct ConstraintEvaluators {
    evals: HashMap<String, Box<dyn ConstraintEvaluator>>,
}

impl ConstraintEvaluators {
    /// An empty registry.
    pub fn new() -> Self {
        ConstraintEvaluators {
            evals: HashMap::new(),
        }
    }

    /// Register an evaluator for its namespace. Replaces any existing
    /// registration for the same namespace and returns it, so callers can
    /// detect accidental double registration.
    pub fn register(
        &mut self,
        ev: Box<dyn ConstraintEvaluator>,
    ) -> Option<Box<dyn ConstraintEvaluator>> {
        self.evals.insert(ev.namespace().as_str().to_string(), ev)
    }

    /// Look up the evaluator for `namespace`.
    pub fn get(&self, namespace: &PurposeId) -> Option<&dyn ConstraintEvaluator> {
        self.evals.get(namespace.as_str()).map(|b| b.as_ref())
    }

    /// Whether the registry is empty (the v1 default).
    pub fn is_empty(&self) -> bool {
        self.evals.is_empty()
    }
}

/// A `RouteState → RouteState` transition with an honest declared
/// [`Manifest`]. Adapters are supplied by clients; Molt ships no executing
/// adapters, only manifest-only [`DeclaredAdapter`] fixtures.
pub trait Adapter: Send + Sync {
    /// Unique adapter id (used in [`Route::hops`] and constraint references).
    fn id(&self) -> &str;
    /// Whether this adapter can act on state `s`.
    fn accepts(&self, s: &RouteState) -> bool;
    /// The state this adapter produces from `s` (sets the output [`Holder`]).
    /// `None` means the adapter cannot act on `s` despite `accepts`.
    fn produces(&self, s: &RouteState) -> Option<RouteState>;
    /// The declared disclosure of this hop.
    fn manifest(&self) -> Manifest;
    /// The declared costs of this hop from state `s`.
    fn quote(&self, s: &RouteState) -> Quote;
    /// What happens if this hop fails mid-route.
    fn recovery(&self) -> RecoverySemantics;
    /// How this hop changes the open segment set; may open, continue, and
    /// close several segments in one hop.
    fn segments(&self) -> SegmentEffects;
    /// Route-wide constraints. Empty for every v1 adapter.
    fn route_constraints(&self) -> &[RouteConstraint] {
        &[]
    }
}

/// A planned (or partially planned) route.
///
/// `states.len() == hops.len() + 1`. `open_segments_at[i]` is the set of
/// segments open across the boundary *after* hop `i` (between hop `i` and hop
/// `i + 1`), so `open_segments_at.len() == hops.len()` and the last entry of
/// a complete route is empty. The invariant holds for every route the
/// planner emits, including rejected partials: a rejected partial records the
/// attempted hop and produced state, and its final `open_segments_at` entry
/// is the pre-attempt open set (the failed hop changed nothing).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Route {
    /// Adapter ids, in order.
    pub hops: Vec<String>,
    /// States visited, starting with the planner's `from` state.
    pub states: Vec<RouteState>,
    /// Segments open after each hop (see type-level docs).
    pub open_segments_at: Vec<Vec<Segment>>,
}

impl Route {
    /// The initial state of the route.
    pub fn start(from: &RouteState) -> Self {
        Route {
            hops: Vec::new(),
            states: vec![from.clone()],
            open_segments_at: Vec::new(),
        }
    }

    /// The current (last) state.
    pub fn current(&self) -> &RouteState {
        // Invariant: states is never empty (Route::start pushes one, the
        // planner only appends). Indexing is safe; no external input path
        // can construct an empty Route except via Deserialize, which the
        // planner/scorer re-validate before use.
        &self.states[self.states.len() - 1]
    }

    /// Segments currently open (after the last hop).
    pub fn open_segments(&self) -> &[Segment] {
        match self.open_segments_at.last() {
            Some(s) => s,
            None => &[],
        }
    }
}

/// The JSON schema of a manifest-only adapter declaration
/// (`fixtures/declared/*.json`). Declared data: it exercises the model, it
/// is never executed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeclaredAdapterFixture {
    /// Adapter id.
    pub id: String,
    /// Human-readable note on what this declaration models.
    pub description: String,
    /// The state template this adapter accepts (structural equality).
    pub accepts: RouteState,
    /// The state this adapter produces.
    pub produces: RouteState,
    /// The declared manifest.
    pub manifest: Manifest,
    /// The declared quote.
    pub quote: Quote,
    /// The declared recovery semantics.
    pub recovery: RecoverySemantics,
    /// The declared segment effects.
    pub segments: SegmentEffects,
    /// Declared route constraints (empty for every v1 adapter).
    #[serde(default)]
    pub constraints: Vec<RouteConstraint>,
}

/// A manifest-only [`Adapter`] built from a [`DeclaredAdapterFixture`].
///
/// Matching is structural equality against the declared `accepts` template;
/// production returns the declared `produces` state. This is the mechanism
/// the S6 `LightningPath`/`SubmarineSwap`/`BoundedTransferStep` declarations
/// and the S11 comparisons use.
#[derive(Clone, Debug)]
pub struct DeclaredAdapter {
    fixture: DeclaredAdapterFixture,
}

impl DeclaredAdapter {
    /// Build from a fixture.
    pub fn new(fixture: DeclaredAdapterFixture) -> Self {
        DeclaredAdapter { fixture }
    }

    /// Parse a fixture from JSON.
    pub fn from_json(json: &str) -> Result<Self, MoltError> {
        let fixture: DeclaredAdapterFixture =
            serde_json::from_str(json).map_err(|e| MoltError::Fixture(e.to_string()))?;
        Ok(DeclaredAdapter::new(fixture))
    }

    /// Load a fixture from a `.json` file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, MoltError> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| MoltError::Fixture(format!("{}: {e}", path.display())))?;
        DeclaredAdapter::from_json(&json)
    }

    /// The underlying fixture.
    pub fn fixture(&self) -> &DeclaredAdapterFixture {
        &self.fixture
    }
}

impl Adapter for DeclaredAdapter {
    fn id(&self) -> &str {
        &self.fixture.id
    }

    fn accepts(&self, s: &RouteState) -> bool {
        s == &self.fixture.accepts
    }

    fn produces(&self, s: &RouteState) -> Option<RouteState> {
        if self.accepts(s) {
            Some(self.fixture.produces.clone())
        } else {
            None
        }
    }

    fn manifest(&self) -> Manifest {
        self.fixture.manifest.clone()
    }

    fn quote(&self, _s: &RouteState) -> Quote {
        self.fixture.quote.clone()
    }

    fn recovery(&self) -> RecoverySemantics {
        self.fixture.recovery.clone()
    }

    fn segments(&self) -> SegmentEffects {
        self.fixture.segments.clone()
    }

    fn route_constraints(&self) -> &[RouteConstraint] {
        &self.fixture.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::Field;

    fn btc_sats(v: u128) -> Amount {
        Amount {
            asset: "BTC".into(),
            units: "sat".into(),
            value: v,
        }
    }

    #[test]
    fn amount_serde_roundtrip() {
        let a = btc_sats(100_000);
        let j = serde_json::to_string(&a).expect("ser");
        let back: Amount = serde_json::from_str(&j).expect("de");
        assert_eq!(back, a);
        assert!(serde_json::from_str::<Amount>("{\"asset\":\"BTC\"}").is_err());
    }

    #[test]
    fn route_state_holder_and_equality() {
        let s = RouteState::Value {
            network: "bitcoin".into(),
            amount: Some(btc_sats(1)),
            holder: Holder::Self_,
        };
        assert_eq!(s.holder(), Holder::Self_);
        let c = RouteState::Custom {
            namespace: PurposeId::parse("pubky.molt.myapp.v1").expect("pid"),
            descriptor: serde_json::json!({"bucket": 7}),
            holder: Holder::Self_,
        };
        let j = serde_json::to_string(&c).expect("ser");
        let back: RouteState = serde_json::from_str(&j).expect("de");
        assert_eq!(back, c);
        assert!(serde_json::from_str::<RouteState>(
            "{\"Custom\":{\"namespace\":\"bad ns\",\"descriptor\":null,\"holder\":\"Self_\"}}"
        )
        .is_err());
    }

    #[test]
    fn route_bookkeeping_helpers() {
        let from = RouteState::Identity {
            scope: IdentityScope::Root,
            holder: Holder::Self_,
        };
        let r = Route::start(&from);
        assert_eq!(r.current(), &from);
        assert!(r.open_segments().is_empty());
    }

    #[test]
    fn declared_adapter_roundtrip_and_matching() {
        let json = r#"{
            "id": "test.step",
            "description": "test adapter",
            "accepts": {"Value": {"network": "bitcoin", "amount": {"asset":"BTC","units":"sat","value":100000}, "holder": "Self_"}},
            "produces": {"Value": {"network": "lightning", "amount": {"asset":"BTC","units":"sat","value":100000}, "holder": "Self_"}},
            "manifest": {"adapter_id": "test.step", "witnesses": [], "preserves": [{"kind":"AMOUNT","namespace":"btc.sats"}], "latency_bound_secs": 30},
            "quote": {"costs": [{"asset":"BTC","units":"sat","value":50}], "latency_secs": 30},
            "recovery": "Atomic",
            "segments": {"opens": [], "continues": [], "closes": []}
        }"#;
        let ad = DeclaredAdapter::from_json(json).expect("parse");
        assert_eq!(ad.id(), "test.step");
        let from = RouteState::Value {
            network: "bitcoin".into(),
            amount: Some(btc_sats(100_000)),
            holder: Holder::Self_,
        };
        assert!(ad.accepts(&from));
        let out = ad.produces(&from).expect("produces");
        assert_eq!(
            out,
            RouteState::Value {
                network: "lightning".into(),
                amount: Some(btc_sats(100_000)),
                holder: Holder::Self_
            }
        );
        let wrong = RouteState::Value {
            network: "bitcoin".into(),
            amount: Some(btc_sats(1)),
            holder: Holder::Self_,
        };
        assert!(!ad.accepts(&wrong));
        assert!(ad.produces(&wrong).is_none());
        assert_eq!(ad.manifest().adapter_id, "test.step");
        assert_eq!(ad.manifest().preserves[0].kind, Field::AMOUNT);
        assert_eq!(ad.recovery(), RecoverySemantics::Atomic);
        assert!(ad.route_constraints().is_empty());
    }

    #[test]
    fn declared_adapter_rejects_bad_json() {
        assert!(DeclaredAdapter::from_json("{}").is_err());
        assert!(DeclaredAdapter::from_json("not json").is_err());
        assert!(DeclaredAdapter::from_file(std::path::Path::new("/nonexistent/x.json")).is_err());
    }

    struct TrueEval(PurposeId);
    impl ConstraintEvaluator for TrueEval {
        fn namespace(&self) -> &PurposeId {
            &self.0
        }
        fn holds(&self, _rule: &serde_json::Value, _route: &Route, _at_hop: usize) -> bool {
            true
        }
    }

    #[test]
    fn constraint_evaluators_register_get_replace() {
        let ns = PurposeId::parse("pubky.molt.myapp.v1").expect("pid");
        let mut evals = ConstraintEvaluators::new();
        assert!(evals.is_empty());
        assert!(evals.get(&ns).is_none());
        assert!(evals.register(Box::new(TrueEval(ns.clone()))).is_none());
        assert!(!evals.is_empty());
        let ev = evals.get(&ns).expect("registered");
        let from = RouteState::Identity {
            scope: IdentityScope::Root,
            holder: Holder::Self_,
        };
        let route = Route::start(&from);
        assert!(ev.holds(&serde_json::Value::Null, &route, 0));
        // Re-registration returns the previous evaluator instead of silently dropping it.
        assert!(evals.register(Box::new(TrueEval(ns))).is_some());
    }
}
