//! Executes `tests/vectors/molt_route_v1.json`: the recorded expectations for
//! S5 (`detach_level`), S6 (`plan`), and S7 (`score`) from S10 of the molt
//! v14 spec. Each case is rebuilt in Rust; the JSON file pins the expected
//! outcomes, constants, and fingerprints.

use pubky_molt::comparisons::{load_baselines, load_declared, run_comparison};
use pubky_molt::planner::{plan, PlannerLimits, RejectReason};
use pubky_molt::route::{
    Adapter, ConstraintEvaluators, DeclaredAdapter, Holder, Quote, RecoverySemantics, Route,
    RouteConstraint, RouteState,
};
use pubky_molt::score::{
    score, Confidence, CostPolicy, SingleAsset, CHEAP, FAST, MAX_DETACH, PRIVATE,
};
use pubky_molt::witness::{
    detach_level, Assumptions, Correlator, CorrelatorSpec, DetachLevel, DomainRegistry, Field,
    Manifest, OperatorId, Segment, SegmentEffects, SegmentId, TraceVerdict, Witness, WitnessRole,
};
use pubky_molt::{from_hex, to_hex, MoltError, PurposeId};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn vectors() -> Value {
    let raw = std::fs::read_to_string(root().join("tests/vectors/molt_route_v1.json"))
        .expect("read vectors");
    serde_json::from_str(&raw).expect("parse vectors")
}

fn case<'a>(suite: &'a [Value], id: &str) -> &'a Value {
    suite
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("missing case {id}"))
}

fn spec(kind: Field, ns: &str) -> CorrelatorSpec {
    CorrelatorSpec::new(kind, ns).expect("valid namespace")
}

fn witness(role: WitnessRole, op: &str, domains: &[&str], lin: Field, lout: Field) -> Witness {
    Witness {
        role,
        operator: OperatorId(op.into()),
        domains: domains
            .iter()
            .map(|d| pubky_molt::witness::ObservationDomain((*d).into()))
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

fn expect_detach_level(expected: &Value, actual: DetachLevel) {
    let want = expected["DetachLevel"]
        .as_str()
        .expect("DetachLevel string");
    let got = format!("{actual:?}");
    assert_eq!(got, want, "detach level mismatch");
}

#[test]
fn vector_suite_header_names_current_spec() {
    let v = vectors();
    assert_eq!(v["suite"].as_str().expect("suite"), "molt_route_v1");
    let spec = v["spec"].as_str().expect("spec");
    assert!(
        spec.starts_with("molt v14 —"),
        "vector suite cites a stale spec version: {spec:?}"
    );
}

#[test]
fn fingerprints_match_pinned_values() {
    let v = vectors();
    for fp in v["fingerprints"].as_array().expect("fingerprints") {
        let ns = fp["namespace"].as_str().expect("ns");
        let value = from_hex(fp["canonical_value_hex"].as_str().expect("hex")).expect("decode");
        // The kind does not affect the fingerprint formula; use TRANSACTION_ID.
        let c = Correlator::new(spec(Field::TRANSACTION_ID, ns), &value);
        assert_eq!(
            to_hex(&c.fingerprint),
            fp["fingerprint"].as_str().expect("fingerprint"),
            "fingerprint drift for {ns}"
        );
    }
}

fn approx(a: f32, b: f64, what: &str) {
    assert!((a as f64 - b).abs() < 1e-6, "{what}: {a} != {b}");
}

#[test]
fn constants_match_code() {
    let v = vectors();
    let cw = &v["constants"]["confidence_weights"];
    approx(
        Confidence::Exact.weight(),
        cw["Exact"].as_f64().unwrap(),
        "c(Exact)",
    );
    approx(
        Confidence::High.weight(),
        cw["High"].as_f64().unwrap(),
        "c(High)",
    );
    approx(
        Confidence::Statistical.weight(),
        cw["Statistical"].as_f64().unwrap(),
        "c(Statistical)",
    );
    let wp = &v["constants"]["weights_presets"];
    for (name, w) in [
        ("FAST", FAST),
        ("CHEAP", CHEAP),
        ("PRIVATE", PRIVATE),
        ("MAX_DETACH", MAX_DETACH),
    ] {
        approx(w.continuity, wp[name]["continuity"].as_f64().unwrap(), name);
        approx(w.cost, wp[name]["cost"].as_f64().unwrap(), name);
        approx(w.latency, wp[name]["latency"].as_f64().unwrap(), name);
    }
    let db = &v["constants"]["detach_bonus"];
    approx(
        pubky_molt::score::detach_bonus(DetachLevel::None),
        db["None"].as_f64().unwrap(),
        "bonus(None)",
    );
    approx(
        pubky_molt::score::detach_bonus(DetachLevel::Unknown),
        db["Unknown"].as_f64().unwrap(),
        "bonus(Unknown)",
    );
    approx(
        pubky_molt::score::detach_bonus(DetachLevel::Independent),
        db["Independent"].as_f64().unwrap(),
        "bonus(Independent)",
    );
    let k = 3u8;
    let expect = db["CollusionBounded_base"].as_f64().unwrap()
        + db["CollusionBounded_per_k"].as_f64().unwrap() * k as f64;
    approx(
        pubky_molt::score::detach_bonus(DetachLevel::CollusionBounded(k)),
        expect,
        "bonus(CB(3))",
    );
    let sev = &v["constants"]["severity"];
    approx(
        pubky_molt::score::severity(Field::ROOT_IDENTITY),
        sev["ROOT_IDENTITY"].as_f64().unwrap(),
        "sev(ROOT)",
    );
    approx(
        pubky_molt::score::severity(Field::RELATIONSHIP_IDENTITY),
        sev["RELATIONSHIP_IDENTITY"].as_f64().unwrap(),
        "sev(REL_ID)",
    );
}

#[test]
fn detach_segment_violation() {
    let v = vectors();
    let c = case(v["detach_cases"].as_array().unwrap(), "segment_violation");
    let reg = DomainRegistry::new();
    let a = manifest("x", vec![], vec![spec(Field::AMOUNT, "btc.sats")]);
    let b = manifest("y", vec![], vec![]);
    let open = vec![Segment {
        id: SegmentId("ln".into()),
        carries: vec![spec(Field::TRANSACTION_ID, "lightning.payment_hash")],
    }];
    let err =
        detach_level(&a, &b, &open, &reg, &Assumptions::default()).expect_err("violation required");
    let expected = &c["expected"]["SegmentViolation"];
    assert_eq!(err.segment.0, expected["segment"].as_str().unwrap());
    assert_eq!(err.missing.len(), 1);
    assert_eq!(err.missing[0].kind, Field::TRANSACTION_ID);
    assert_eq!(err.missing[0].namespace, "lightning.payment_hash");
}

#[test]
fn detach_spec_leaking_past_close() {
    let v = vectors();
    let c = case(
        v["detach_cases"].as_array().unwrap(),
        "spec_leaking_past_close",
    );
    let reg = DomainRegistry::new();
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
    let b = manifest("next", vec![], vec![]);
    let level = detach_level(&a, &b, &[], &reg, &Assumptions::default()).expect("no violation");
    expect_detach_level(&c["expected"], level);
}

#[test]
fn detach_unknown_from_unregistered_witnesses() {
    let v = vectors();
    let c = case(
        v["detach_cases"].as_array().unwrap(),
        "unknown_unregistered_witnesses",
    );
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
    let level = detach_level(&a, &b, &[], &reg, &asm).expect("ok");
    expect_detach_level(&c["expected"], level);
    let asm2 = Assumptions {
        treat_unknown_as_independent: true,
        ..asm
    };
    let level2 = detach_level(&a, &b, &[], &reg, &asm2).expect("ok");
    expect_detach_level(&c["expected_when_treated_independent"], level2);
}

#[test]
fn detach_after_close_and_open_one_hop() {
    let v = vectors();
    let c = case(
        v["detach_cases"].as_array().unwrap(),
        "close_and_open_one_hop",
    );
    let reg = DomainRegistry::new();
    // A swap-shaped hop closed segment A and opened segment B in one hop. The
    // boundary after it carries only B; B's carries are preserved, so no leak.
    let b_carries = spec(Field::TRANSACTION_ID, "swap.hash");
    let a = manifest("swap-hop", vec![], vec![b_carries.clone()]);
    let b = manifest("next", vec![], vec![b_carries.clone()]);
    let open = vec![Segment {
        id: SegmentId("b".into()),
        carries: vec![b_carries],
    }];
    let level = detach_level(&a, &b, &open, &reg, &Assumptions::default()).expect("ok");
    expect_detach_level(&c["expected"], level);
}

// ---- plan cases ----

fn value(net: &str, holder: Holder) -> RouteState {
    RouteState::Value {
        network: net.into(),
        amount: None,
        holder,
    }
}

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

fn has_reject(res: &pubky_molt::planner::PlanResult, pred: impl Fn(&RejectReason) -> bool) -> bool {
    res.rejected.iter().any(|(_, r)| pred(r))
}

#[test]
fn plan_refuses_counterparty_held_extensions() {
    let v = vectors();
    let lim = PlannerLimits::default();
    let evals = ConstraintEvaluators::new();
    for (case_id, file) in [
        (
            "refuse_counterparty_extension_bts",
            "bounded_transfer_step.json",
        ),
        (
            "refuse_counterparty_extension_lightning",
            "lightning_path.json",
        ),
    ] {
        let c = case(v["plan_cases"].as_array().unwrap(), case_id);
        assert_eq!(c["expected_reject"].as_str().unwrap(), "HolderNotSelf");
        assert!(c["expected_accept_as_goal"].as_bool().unwrap());
        let ad = DeclaredAdapter::from_file(&root().join("fixtures/declared").join(file))
            .expect("fixture");
        let beyond = TestAdapter::new(
            "beyond",
            vec![ad.fixture().produces.clone()],
            value("beyond", Holder::Self_),
        );
        let adapters: Vec<&dyn Adapter> = vec![&ad, &beyond];
        let from = ad.fixture().accepts.clone();
        // Accepted when the Counterparty-held output IS the goal.
        let ok = plan(
            &from,
            &ad.fixture().produces.clone(),
            &adapters,
            &evals,
            &lim,
        );
        assert_eq!(
            ok.routes.len(),
            1,
            "{case_id}: goal must accept Counterparty-held output"
        );
        // Refused past it.
        let no = plan(
            &from,
            &value("beyond", Holder::Self_),
            &adapters,
            &evals,
            &lim,
        );
        assert!(no.routes.is_empty(), "{case_id}");
        assert!(
            has_reject(&no, |r| matches!(r, RejectReason::HolderNotSelf)),
            "{case_id}"
        );
    }
}

#[test]
fn plan_rejects_unclosed_segment_and_duplicate_id() {
    let v = vectors();
    let lim = PlannerLimits::default();
    let evals = ConstraintEvaluators::new();

    let c1 = case(v["plan_cases"].as_array().unwrap(), "unclosed_segment");
    let seg = Segment {
        id: SegmentId(
            c1["expected_reject"]["UnclosedSegment"]
                .as_str()
                .unwrap()
                .into(),
        ),
        carries: vec![spec(Field::OBLIGATION_ID, "credit.receipt_id")],
    };
    let mut opener = TestAdapter::new(
        "opener",
        vec![value("a", Holder::Self_)],
        value("b", Holder::Self_),
    );
    opener.effects.opens = vec![seg.clone()];
    opener.manifest.preserves = vec![spec(Field::OBLIGATION_ID, "credit.receipt_id")];
    let adapters: Vec<&dyn Adapter> = vec![&opener];
    let res = plan(
        &value("a", Holder::Self_),
        &value("b", Holder::Self_),
        &adapters,
        &evals,
        &lim,
    );
    assert!(res.routes.is_empty());
    assert!(has_reject(
        &res,
        |r| matches!(r, RejectReason::UnclosedSegment(id) if id.0 == "step")
    ));

    let c2 = case(v["plan_cases"].as_array().unwrap(), "duplicate_segment_id");
    assert_eq!(
        c2["expected_reject"]["DuplicateSegmentId"]
            .as_str()
            .unwrap(),
        "ln"
    );
    let ln_seg = Segment {
        id: SegmentId("ln".into()),
        carries: vec![spec(Field::TRANSACTION_ID, "lightning.payment_hash")],
    };
    let mut o1 = TestAdapter::new(
        "o1",
        vec![value("a", Holder::Self_)],
        value("b", Holder::Self_),
    );
    o1.effects.opens = vec![ln_seg.clone()];
    o1.manifest.preserves = vec![spec(Field::TRANSACTION_ID, "lightning.payment_hash")];
    let mut o2 = TestAdapter::new(
        "o2",
        vec![value("b", Holder::Self_)],
        value("c", Holder::Self_),
    );
    o2.effects.opens = vec![ln_seg];
    let adapters2: Vec<&dyn Adapter> = vec![&o1, &o2];
    let res2 = plan(
        &value("a", Holder::Self_),
        &value("c", Holder::Self_),
        &adapters2,
        &evals,
        &lim,
    );
    assert!(res2.routes.is_empty());
    assert!(has_reject(
        &res2,
        |r| matches!(r, RejectReason::DuplicateSegmentId(id) if id.0 == "ln")
    ));
}

#[test]
fn plan_accepts_submarine_swap_then_lightning() {
    let v = vectors();
    let c = case(
        v["plan_cases"].as_array().unwrap(),
        "accept_submarine_swap_then_lightning",
    );
    let dir = root().join("fixtures/declared");
    let swap = DeclaredAdapter::from_file(&dir.join("submarine_swap.json")).expect("swap");
    let ln = DeclaredAdapter::from_file(&dir.join("lightning_path.json")).expect("ln");
    let adapters: Vec<&dyn Adapter> = vec![&swap, &ln];
    let res = plan(
        &swap.fixture().accepts.clone(),
        &ln.fixture().produces.clone(),
        &adapters,
        &ConstraintEvaluators::new(),
        &PlannerLimits::default(),
    );
    assert_eq!(res.routes.len(), 1, "rejected: {:?}", res.rejected);
    let expected: Vec<&str> = c["expected_hops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap())
        .collect();
    assert_eq!(res.routes[0].hops, expected);
}

#[test]
fn plan_enforces_not_repeatable_and_exclusive_adjacency() {
    let v = vectors();
    let lim = PlannerLimits::default();
    let evals = ConstraintEvaluators::new();

    let _c1 = case(v["plan_cases"].as_array().unwrap(), "not_repeatable");
    let mut a1 = TestAdapter::new(
        "nr",
        vec![value("a", Holder::Self_)],
        value("b", Holder::Self_),
    );
    a1.constraints = vec![RouteConstraint::NotRepeatable];
    let mut a2 = TestAdapter::new(
        "nr",
        vec![value("b", Holder::Self_)],
        value("c", Holder::Self_),
    );
    a2.constraints = vec![RouteConstraint::NotRepeatable];
    let adapters: Vec<&dyn Adapter> = vec![&a1, &a2];
    let res = plan(
        &value("a", Holder::Self_),
        &value("c", Holder::Self_),
        &adapters,
        &evals,
        &lim,
    );
    assert!(res.routes.is_empty());
    assert!(has_reject(&res, |r| matches!(
        r,
        RejectReason::Constraint(RouteConstraint::NotRepeatable)
    )));

    let _c2 = case(v["plan_cases"].as_array().unwrap(), "exclusive_adjacency");
    let mut e = TestAdapter::new(
        "e",
        vec![value("s0", Holder::Self_)],
        value("s1", Holder::Self_),
    );
    e.constraints = vec![RouteConstraint::ExclusiveAdjacency("b".into())];
    let b = TestAdapter::new(
        "b",
        vec![value("s1", Holder::Self_)],
        value("s2", Holder::Self_),
    );
    let adapters2: Vec<&dyn Adapter> = vec![&e, &b];
    // Adjacent to b: accepted.
    let ok = plan(
        &value("s0", Holder::Self_),
        &value("s2", Holder::Self_),
        &adapters2,
        &evals,
        &lim,
    );
    assert_eq!(ok.routes.len(), 1);
    // Final hop without b: rejected.
    let no = plan(
        &value("s0", Holder::Self_),
        &value("s1", Holder::Self_),
        &adapters2,
        &evals,
        &lim,
    );
    assert!(no.routes.is_empty());
    assert!(has_reject(
        &no,
        |r| matches!(r, RejectReason::Constraint(RouteConstraint::ExclusiveAdjacency(x)) if x == "b")
    ));
}

#[test]
fn plan_routes_through_custom_state() {
    let v = vectors();
    let c = case(
        v["plan_cases"].as_array().unwrap(),
        "route_through_custom_state",
    );
    let ns = PurposeId::parse(c["custom_namespace"].as_str().unwrap()).expect("pid");
    let custom = RouteState::Custom {
        namespace: ns,
        descriptor: serde_json::json!({"slot": 3}),
        holder: Holder::Self_,
    };
    let c1 = TestAdapter::new("c1", vec![value("s0", Holder::Self_)], custom.clone());
    let c2 = TestAdapter::new("c2", vec![custom], value("s2", Holder::Self_));
    let adapters: Vec<&dyn Adapter> = vec![&c1, &c2];
    let res = plan(
        &value("s0", Holder::Self_),
        &value("s2", Holder::Self_),
        &adapters,
        &ConstraintEvaluators::new(),
        &PlannerLimits::default(),
    );
    assert_eq!(res.routes.len(), 1);
    let expected: Vec<&str> = c["expected_hops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap())
        .collect();
    assert_eq!(res.routes[0].hops, expected);
}

#[test]
fn plan_custom_constraint_fails_closed() {
    let v = vectors();
    let c = case(
        v["plan_cases"].as_array().unwrap(),
        "custom_constraint_fail_closed",
    );
    let ns = PurposeId::parse(
        c["expected_reject"]["UnsupportedConstraint"]["namespace"]
            .as_str()
            .unwrap(),
    )
    .expect("pid");
    let mut ad = TestAdapter::new(
        "guarded",
        vec![value("s0", Holder::Self_)],
        value("s1", Holder::Self_),
    );
    ad.constraints = vec![RouteConstraint::Custom {
        namespace: ns,
        rule: serde_json::json!({"min": 1}),
    }];
    let adapters: Vec<&dyn Adapter> = vec![&ad];
    let res = plan(
        &value("s0", Holder::Self_),
        &value("s1", Holder::Self_),
        &adapters,
        &ConstraintEvaluators::new(),
        &PlannerLimits::default(),
    );
    assert!(res.routes.is_empty());
    assert!(has_reject(&res, |r| matches!(
        r,
        RejectReason::UnsupportedConstraint { namespace, adapter }
            if namespace.as_str() == "pubky.molt.policy.v1" && adapter == "guarded"
    )));
}

#[test]
fn plan_close_and_open_one_hop() {
    let v = vectors();
    let c = case(
        v["plan_cases"].as_array().unwrap(),
        "close_and_open_one_hop_plans",
    );
    let a_seg = Segment {
        id: SegmentId("a".into()),
        carries: vec![spec(Field::TRANSACTION_ID, "bitcoin.txid")],
    };
    let b_seg = Segment {
        id: SegmentId("b".into()),
        carries: vec![spec(Field::TRANSACTION_ID, "swap.hash")],
    };
    let mut open_a = TestAdapter::new(
        "open_a",
        vec![value("s0", Holder::Self_)],
        value("s1", Holder::Self_),
    );
    open_a.effects.opens = vec![a_seg.clone()];
    open_a.manifest.preserves = vec![spec(Field::TRANSACTION_ID, "bitcoin.txid")];
    // The swap hop: closes A, opens B, in one hop. It must preserve A's
    // carries across its input boundary and B's across its output boundary.
    let mut swap = TestAdapter::new(
        "swap_a_to_b",
        vec![value("s1", Holder::Self_)],
        value("s2", Holder::Self_),
    );
    swap.effects.continues = vec![a_seg.id.clone()];
    swap.effects.closes = vec![a_seg.id.clone()];
    swap.effects.opens = vec![b_seg.clone()];
    swap.manifest.preserves = vec![
        spec(Field::TRANSACTION_ID, "bitcoin.txid"),
        spec(Field::TRANSACTION_ID, "swap.hash"),
    ];
    let mut close_b = TestAdapter::new(
        "close_b",
        vec![value("s2", Holder::Self_)],
        value("s3", Holder::Self_),
    );
    close_b.effects.continues = vec![b_seg.id.clone()];
    close_b.effects.closes = vec![b_seg.id.clone()];
    close_b.manifest.preserves = vec![spec(Field::TRANSACTION_ID, "swap.hash")];
    let adapters: Vec<&dyn Adapter> = vec![&open_a, &swap, &close_b];
    let res = plan(
        &value("s0", Holder::Self_),
        &value("s3", Holder::Self_),
        &adapters,
        &ConstraintEvaluators::new(),
        &PlannerLimits::default(),
    );
    assert_eq!(res.routes.len(), 1, "rejected: {:?}", res.rejected);
    let expected: Vec<&str> = c["expected_hops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap())
        .collect();
    assert_eq!(res.routes[0].hops, expected);
    assert!(res.routes[0].open_segments().is_empty());
}

// ---- score cases ----

struct CostAdapter {
    id: String,
    costs: Vec<pubky_molt::route::Amount>,
}

impl Adapter for CostAdapter {
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
        Manifest {
            adapter_id: self.id.clone(),
            witnesses: vec![],
            preserves: vec![],
            latency_bound_secs: Some(1),
        }
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
        SegmentEffects::default()
    }
}

#[test]
fn score_single_asset_mismatch_and_multi_asset_ok() {
    let v = vectors();
    let c1 = case(
        v["score_cases"].as_array().unwrap(),
        "single_asset_rejects_mixed",
    );
    assert_eq!(c1["expected_error"].as_str().unwrap(), "Cost");
    let ad = CostAdapter {
        id: "h".into(),
        costs: vec![
            pubky_molt::route::Amount {
                asset: "BTC".into(),
                units: "sat".into(),
                value: 10,
            },
            pubky_molt::route::Amount {
                asset: "USD".into(),
                units: "cent".into(),
                value: 5,
            },
        ],
    };
    let route = Route {
        hops: vec!["h".into()],
        states: vec![value("n", Holder::Self_), value("n", Holder::Self_)],
        open_segments_at: vec![vec![]],
    };
    let adapters: Vec<&dyn Adapter> = vec![&ad];
    let err = score(
        &route,
        &adapters,
        &DomainRegistry::new(),
        &Assumptions::default(),
        &PRIVATE,
        &SingleAsset::new("BTC", "sat"),
    )
    .expect_err("SingleAsset must reject mixed assets");
    assert!(matches!(err, pubky_molt::score::ScoreError::Cost(_)));

    struct Multi;
    impl CostPolicy for Multi {
        fn reduce(&self, costs: &[pubky_molt::route::Amount]) -> Result<f32, MoltError> {
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
    .expect("multi-asset policy must accept");
    let c2 = case(
        v["score_cases"].as_array().unwrap(),
        "multi_asset_policy_reduces",
    );
    assert_eq!(
        ok.reduced_cost as f64,
        c2["expected_reduced_cost"].as_f64().unwrap()
    );
}

// ---- trace cases ----

#[test]
fn trace_confirms_and_refutes_predicted_join() {
    let v = vectors();
    for (id, want) in [
        ("confirm_exact_join", TraceVerdict::Confirmed),
        ("refute_exact_join", TraceVerdict::Refuted),
    ] {
        let c = case(v["trace_cases"].as_array().unwrap(), id);
        assert_eq!(c["expected"].as_str().unwrap(), format!("{want:?}"));
        let s = spec(
            Field::TRANSACTION_ID,
            c["spec"]["namespace"].as_str().unwrap(),
        );
        let v0 = from_hex(c["value_at_0_hex"].as_str().unwrap()).expect("hex");
        let v2 = from_hex(c["value_at_2_hex"].as_str().unwrap()).expect("hex");
        let trace = pubky_molt::witness::RouteTrace {
            crossings: vec![
                (0, vec![Correlator::new(s.clone(), &v0)]),
                (2, vec![Correlator::new(s.clone(), &v2)]),
            ],
        };
        assert_eq!(trace.check_predicted_join(0, 2, &s), want, "{id}");
    }
}

// ---- S11 comparison confidences ----

#[test]
fn comparison_confidences_match_vectors() {
    let v = vectors();
    let fixtures = root().join("fixtures");
    let baselines = load_baselines(&fixtures.join("baselines")).expect("baselines");
    let declared = load_declared(&fixtures.join("declared")).expect("declared");
    let cc = &v["comparison_confidences"];
    for b in &baselines {
        let entry = &cc[&b.name];
        assert!(
            entry.is_object(),
            "missing comparison_confidences for {}",
            b.name
        );
        let c = run_comparison(b, &declared, &PRIVATE).expect("comparison");
        let elim: Vec<String> = c
            .joins_eliminated
            .iter()
            .map(|j| format!("{:?}", j.confidence))
            .collect();
        let rem: Vec<String> = c
            .molt_score
            .joins
            .iter()
            .map(|j| format!("{:?}", j.confidence))
            .collect();
        let want_elim: Vec<&str> = entry["eliminated"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        let want_rem: Vec<&str> = entry["remaining"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(elim, want_elim, "{}: eliminated confidences", b.name);
        assert_eq!(rem, want_rem, "{}: remaining confidences", b.name);
    }
}
