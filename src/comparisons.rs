//! S11. Comparative claims, as scorer vectors.
//!
//! Each comparison is a pair of routes built from honest [`Manifest`]s: a
//! **baseline** (a manifest-only fixture under `fixtures/baselines/`, never
//! executed) and a **Molt route** planned by [`crate::planner::plan`] from
//! declared adapters. [`render_comparisons`] scores both, and the crate-level
//! doc test pins the rendered `docs/COMPARISONS.md`, so the claims cannot
//! drift from the code. These are test vectors first and marketing never.

use crate::planner::{plan, PlannerLimits};
use crate::route::{
    Adapter, ConstraintEvaluators, DeclaredAdapter, DeclaredAdapterFixture, Holder, Route,
    RouteState,
};
use crate::score::{score, JoinReport, RouteScore, Weights, PRIVATE};
use crate::witness::{Assumptions, DomainRegistry, Manifest};
use crate::MoltError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The JSON schema of a baseline comparison fixture
/// (`fixtures/baselines/*.json`). Every baseline records its assumptions,
/// provenance, and omissions: these are illustrative model fixtures, not
/// empirical security benchmarks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BaselineFixture {
    /// Short slug (file name).
    pub name: String,
    /// Section title (e.g. "A. Private payment vs CoinJoin").
    pub title: String,
    /// What the baseline models.
    pub summary: String,
    /// The assumption set both sides of the comparison are scored under.
    pub assumptions: Assumptions,
    /// Where this model of the baseline comes from.
    pub provenance: String,
    /// What this model deliberately leaves out.
    pub omitted: Vec<String>,
    /// When the Molt route is not the better choice.
    pub not_better_when: String,
    /// Adapter ids forming the Molt route (planned, then scored).
    pub molt_route: Vec<String>,
    /// The baseline's honest manifest.
    pub manifest: Manifest,
    /// Honest prose notes about residual joins the scorer cannot express.
    #[serde(default)]
    pub joins_remaining_notes: Vec<String>,
}

impl BaselineFixture {
    /// Parse a baseline fixture from JSON, enforcing the S11 honesty fields.
    pub fn from_json(json: &str) -> Result<Self, MoltError> {
        let f: BaselineFixture =
            serde_json::from_str(json).map_err(|e| MoltError::Fixture(format!("baseline: {e}")))?;
        if f.provenance.trim().is_empty() {
            return Err(MoltError::Fixture(format!(
                "baseline {:?}: missing provenance",
                f.name
            )));
        }
        if f.omitted.is_empty() {
            return Err(MoltError::Fixture(format!(
                "baseline {:?}: missing omitted",
                f.name
            )));
        }
        if f.molt_route.is_empty() {
            return Err(MoltError::Fixture(format!(
                "baseline {:?}: missing molt_route",
                f.name
            )));
        }
        Ok(f)
    }

    /// Load a baseline fixture from a `.json` file.
    pub fn from_file(path: &Path) -> Result<Self, MoltError> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| MoltError::Fixture(format!("{}: {e}", path.display())))?;
        BaselineFixture::from_json(&json)
    }
}

/// Is `p` a real `.json` fixture file (not a macOS `._*` AppleDouble
/// metadata sidecar, which some filesystems sprinkle into directories)?
fn is_fixture_json(p: &Path) -> bool {
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    !name.starts_with("._") && p.extension().map(|x| x == "json").unwrap_or(false)
}

/// Load every baseline fixture in `dir`, sorted by title for deterministic
/// output.
pub fn load_baselines(dir: &Path) -> Result<Vec<BaselineFixture>, MoltError> {
    let mut out = Vec::new();
    let mut paths: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| MoltError::Fixture(format!("{}: {e}", dir.display())))?;
    for e in entries {
        let e = e.map_err(|err| MoltError::Fixture(err.to_string()))?;
        if is_fixture_json(&e.path()) {
            paths.push(e.path());
        }
    }
    paths.sort();
    for p in paths {
        out.push(BaselineFixture::from_file(&p)?);
    }
    out.sort_by(|a, b| a.title.cmp(&b.title));
    Ok(out)
}

/// Load every declared adapter fixture in `dir`.
pub fn load_declared(dir: &Path) -> Result<Vec<DeclaredAdapter>, MoltError> {
    let mut out = Vec::new();
    let mut paths: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| MoltError::Fixture(format!("{}: {e}", dir.display())))?;
    for e in entries {
        let e = e.map_err(|err| MoltError::Fixture(err.to_string()))?;
        if is_fixture_json(&e.path()) {
            paths.push(e.path());
        }
    }
    paths.sort();
    for p in paths {
        out.push(DeclaredAdapter::from_file(&p)?);
    }
    Ok(out)
}

/// The illustrative Molt-side adapters used by the comparisons:
/// `molt.intro.session` (S9 `IntroAdapter` in `SessionAuthenticated` mode),
/// `molt.drop.channel` (S8/S9 Drop relay manifest), and
/// `molt.payment.intent` (local application intent crossing no network, so
/// its manifest has no witnesses). Their *manifests* mirror S8/S9; their
/// state chaining is illustrative — the executing adapters live in paykit-rs.
pub fn comparison_adapters() -> Result<Vec<DeclaredAdapter>, MoltError> {
    const INTRO: &str = r#"{
        "id": "molt.intro.session",
        "description": "IntroAdapter (S9) in SessionAuthenticated (Noise) mode: the counterparty learns ROOT_IDENTITY only. Illustrative declared data mirroring S9.",
        "accepts": { "Identity": { "scope": "Root", "holder": "Self_" } },
        "produces": { "Identity": { "scope": "Pairwise", "holder": "Self_" } },
        "manifest": {
            "adapter_id": "molt.intro.session",
            "witnesses": [
                {
                    "role": "Counterparty",
                    "operator": "counterparty",
                    "domains": [],
                    "learns_in": "ROOT_IDENTITY",
                    "learns_out": "ROOT_IDENTITY"
                }
            ],
            "preserves": [],
            "latency_bound_secs": 5
        },
        "quote": { "costs": [], "latency_secs": 5 },
        "recovery": "Idempotent",
        "segments": { "opens": [], "continues": [], "closes": [] }
    }"#;
    const DROP: &str = r#"{
        "id": "molt.drop.channel",
        "description": "DropTransportAdapter (S9) onto a Drop relay (S8): the relay learns NETWORK_LOCATION | TIME | CONTENT_SIZE | RELATIONSHIP_LINK (poll-pattern). Destinations are opaque channel ids. Illustrative declared data mirroring S8.",
        "accepts": { "Identity": { "scope": "Pairwise", "holder": "Self_" } },
        "produces": { "Transport": { "network": "drop", "endpoint_kind": "opaque-channel", "holder": "Self_" } },
        "manifest": {
            "adapter_id": "molt.drop.channel",
            "witnesses": [
                {
                    "role": "RelayOperator",
                    "operator": "relay-op-1",
                    "domains": ["relay-co-1"],
                    "learns_in": "NETWORK_LOCATION | TIME | CONTENT_SIZE | RELATIONSHIP_LINK",
                    "learns_out": "NETWORK_LOCATION | TIME | CONTENT_SIZE | RELATIONSHIP_LINK"
                }
            ],
            "preserves": [{ "kind": "CONTENT_SIZE", "namespace": "wire.bytes" }],
            "latency_bound_secs": 60
        },
        "quote": { "costs": [], "latency_secs": 60 },
        "recovery": "BestEffort",
        "segments": { "opens": [], "continues": [], "closes": [] }
    }"#;
    const INTENT: &str = r#"{
        "id": "molt.payment.intent",
        "description": "Application intent: the principal decides to pay over the open channel. Local, crosses no network, so its manifest has no witnesses. Illustrative declared data.",
        "accepts": { "Transport": { "network": "drop", "endpoint_kind": "opaque-channel", "holder": "Self_" } },
        "produces": { "Value": { "network": "credit-line", "amount": { "asset": "USD", "units": "cent", "value": 2500 }, "holder": "Self_" } },
        "manifest": { "adapter_id": "molt.payment.intent", "witnesses": [], "preserves": [], "latency_bound_secs": 0 },
        "quote": { "costs": [], "latency_secs": 0 },
        "recovery": "Idempotent",
        "segments": { "opens": [], "continues": [], "closes": [] }
    }"#;
    Ok(vec![
        DeclaredAdapter::from_json(INTRO)?,
        DeclaredAdapter::from_json(DROP)?,
        DeclaredAdapter::from_json(INTENT)?,
    ])
}

/// A [`crate::score::CostPolicy`] used only for rendering comparisons: sums
/// all quoted values regardless of asset. Illustrative (the comparisons
/// render the raw heterogeneous costs alongside); never make routing
/// decisions from it.
struct SumAll;

impl crate::score::CostPolicy for SumAll {
    fn reduce(&self, costs: &[crate::route::Amount]) -> Result<f32, MoltError> {
        Ok(costs.iter().map(|c| c.value as f32).sum())
    }
}

/// One scored comparison: baseline vs Molt route.
#[derive(Clone, Debug)]
pub struct ComparisonResult {
    /// The baseline fixture.
    pub baseline: BaselineFixture,
    /// Score of the baseline, treated as a single-hop route.
    pub baseline_score: RouteScore,
    /// The planned Molt route.
    pub molt_route: Route,
    /// Score of the Molt route.
    pub molt_score: RouteScore,
    /// Baseline joins with no counterpart (same domain set and kinds) in the
    /// Molt route's joins.
    pub joins_eliminated: Vec<JoinReport>,
}

/// Run one comparison: plan the fixture's Molt route, score both sides under
/// the fixture's assumptions.
pub fn run_comparison(
    baseline: &BaselineFixture,
    declared: &[DeclaredAdapter],
    w: &Weights,
) -> Result<ComparisonResult, MoltError> {
    let reg = DomainRegistry::new();

    // Baseline as a single-hop route.
    let baseline_state = || RouteState::Value {
        network: "baseline".into(),
        amount: None,
        holder: Holder::Self_,
    };
    let baseline_adapter = DeclaredAdapter::new(DeclaredAdapterFixture {
        id: baseline.manifest.adapter_id.clone(),
        description: baseline.summary.clone(),
        accepts: baseline_state(),
        produces: baseline_state(),
        manifest: baseline.manifest.clone(),
        quote: crate::route::Quote {
            costs: vec![],
            latency_secs: baseline.manifest.latency_bound_secs.unwrap_or(0),
        },
        recovery: crate::route::RecoverySemantics::BestEffort,
        segments: Default::default(),
        constraints: vec![],
    });
    let baseline_route = Route {
        hops: vec![baseline_adapter.id().to_string()],
        states: vec![baseline_state(), baseline_state()],
        open_segments_at: vec![vec![]],
    };
    let baseline_adapters: Vec<&dyn Adapter> = vec![&baseline_adapter];
    let baseline_score = score(
        &baseline_route,
        &baseline_adapters,
        &reg,
        &baseline.assumptions,
        w,
        &SumAll,
    )
    .map_err(|e| MoltError::Fixture(format!("baseline {:?} unscorable: {e}", baseline.name)))?;

    // Plan the Molt route from the fixture's hop id list.
    let mut all: Vec<DeclaredAdapter> = comparison_adapters()?;
    all.extend(declared.iter().cloned());
    let planned_adapters: Vec<&dyn Adapter> = all.iter().map(|d| d as &dyn Adapter).collect();
    let first = all
        .iter()
        .find(|a| a.id() == baseline.molt_route[0])
        .ok_or_else(|| {
            MoltError::Fixture(format!(
                "{}: unknown first hop {:?}",
                baseline.name, baseline.molt_route[0]
            ))
        })?;
    let last = all
        .iter()
        .find(|a| a.id() == baseline.molt_route[baseline.molt_route.len() - 1])
        .ok_or_else(|| MoltError::Fixture(format!("{}: unknown last hop", baseline.name)))?;
    let from = first.fixture().accepts.clone();
    let to = last.fixture().produces.clone();
    let evals = ConstraintEvaluators::new();
    let res = plan(
        &from,
        &to,
        &planned_adapters,
        &evals,
        &PlannerLimits::default(),
    );
    let molt_route = res
        .routes
        .into_iter()
        .find(|r| r.hops == baseline.molt_route)
        .ok_or_else(|| {
            MoltError::Fixture(format!(
                "{}: molt route {:?} did not plan; rejected: {:?}",
                baseline.name, baseline.molt_route, res.rejected
            ))
        })?;
    let molt_adapters: Vec<&dyn Adapter> = all.iter().map(|d| d as &dyn Adapter).collect();
    let molt_score = score(
        &molt_route,
        &molt_adapters,
        &reg,
        &baseline.assumptions,
        w,
        &SumAll,
    )
    .map_err(|e| MoltError::Fixture(format!("{}: molt route unscorable: {e}", baseline.name)))?;

    let molt_keys: BTreeSet<(Vec<String>, BTreeSet<String>)> =
        molt_score.joins.iter().map(join_key).collect();
    let joins_eliminated: Vec<JoinReport> = baseline_score
        .joins
        .iter()
        .filter(|j| !molt_keys.contains(&join_key(j)))
        .cloned()
        .collect();

    Ok(ComparisonResult {
        baseline: baseline.clone(),
        baseline_score,
        molt_route,
        molt_score,
        joins_eliminated,
    })
}

fn join_key(j: &JoinReport) -> (Vec<String>, BTreeSet<String>) {
    let domains: Vec<String> = j.domain_set.iter().map(|d| d.0.clone()).collect();
    let kinds: BTreeSet<String> = j.via.iter().map(|v| format!("{:?}", v.kind)).collect();
    (domains, kinds)
}

fn render_join(j: &JoinReport) -> String {
    let domains = j
        .domain_set
        .iter()
        .map(|d| format!("`{}`", d.0))
        .collect::<Vec<_>>()
        .join(" + ");
    let via = j
        .via
        .iter()
        .map(|v| {
            if v.namespace.is_empty() {
                format!("{:?}", v.kind)
            } else {
                format!("{:?} (`{}`)", v.kind, v.namespace)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let points = j
        .joins
        .iter()
        .map(|(i, j)| format!("{i}↔{j}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "- {domains} joins observation points {points} via {via} (confidence: {:?})",
        j.confidence
    )
}

fn render_detaches(score: &RouteScore) -> String {
    score
        .detaches
        .iter()
        .enumerate()
        .map(|(i, d)| format!("hop {i}: {d:?}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Render `docs/COMPARISONS.md` from the committed fixtures under
/// `fixtures/`. The crate-level doc test pins the output.
pub fn render_comparisons() -> Result<String, MoltError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    render_comparisons_from(&root)
}

/// Render the comparisons document from an explicit fixtures directory
/// containing `baselines/` and `declared/` subdirectories.
pub fn render_comparisons_from(fixtures: &Path) -> Result<String, MoltError> {
    let baselines = load_baselines(&fixtures.join("baselines"))?;
    let declared = load_declared(&fixtures.join("declared"))?;
    let w = PRIVATE;

    let mut out = String::new();
    out.push_str("# Molt comparisons (generated)\n\n");
    out.push_str("Illustrative model fixtures, not empirical security benchmarks.\n\n");
    out.push_str("Generated by `pubky_molt::comparisons::render_comparisons` from `fixtures/baselines/*.json` \\\n");
    out.push_str("and `fixtures/declared/*.json`, and pinned by the crate-level doc test. Do not edit by hand; \\\n");
    out.push_str("regenerate with `MOLT_COMPARISONS_REGENERATE=1 cargo test --doc` and commit the result.\n\n");
    out.push_str("Method: each comparison scores a manifest-only **baseline** fixture (never executed) and a \\\n");
    out.push_str("**Molt route** produced by the bounded planner from declared adapters, under the baseline's own \\\n");
    out.push_str("recorded assumption set. Scoring constants (recorded in `tests/vectors/molt_route_v1.json`): \\\n");
    out.push_str("confidence weights Exact=1.0, High=0.8, Statistical=0.3; colluding-set weight `w(|S|)=1/|S|`; \\\n");
    out.push_str(
        "detach bonus None=0, Unknown=0.1, Independent=1.0, CollusionBounded(k)=1.0+0.5k; \\\n",
    );
    out.push_str("severity ROOT_IDENTITY=100 ≫ RELATIONSHIP_IDENTITY=25 ≫ PAIRWISE_KEY=20 ≫ identifiers=10 > \\\n");
    out.push_str("AMOUNT/TIME=5 > RELATIONSHIP_LINK=2 > other=1. Weights preset: PRIVATE \\\n");
    out.push_str("(continuity=0.7, cost=0.2, latency=0.1). None of the detach levels below claims resistance \\\n");
    out.push_str("to a global passive observer.\n");

    for b in &baselines {
        let c = run_comparison(b, &declared, &w)?;
        out.push_str(&format!("\n## {} (`{}`)\n\n", b.title, b.name));
        out.push_str(&format!("**Baseline.** {}\n\n", b.summary));
        out.push_str(&format!(
            "**Assumptions.** colluding_set_size={}, time_window_secs={}, treat_unknown_as_independent={}.\n\n",
            b.assumptions.colluding_set_size, b.assumptions.time_window_secs, b.assumptions.treat_unknown_as_independent
        ));
        out.push_str(&format!("**Provenance.** {}\n\n", b.provenance));
        out.push_str("**Omitted.**\n");
        for o in &b.omitted {
            out.push_str(&format!("- {o}\n"));
        }
        out.push_str(&format!(
            "\n**Scores (PRIVATE weights).** Baseline continuity cost `{:.4}` ({} joins; detaches: {}). \\\n",
            c.baseline_score.continuity_cost,
            c.baseline_score.joins.len(),
            render_detaches(&c.baseline_score)
        ));
        out.push_str(&format!(
            "Molt route `{}` continuity cost `{:.4}` ({} joins; detaches: {}).\n\n",
            c.molt_route.hops.join(" → "),
            c.molt_score.continuity_cost,
            c.molt_score.joins.len(),
            render_detaches(&c.molt_score)
        ));
        let verdict = if c.molt_score.continuity_cost < c.baseline_score.continuity_cost {
            format!(
                "**yes** (`{:.4}` < `{:.4}`)",
                c.molt_score.continuity_cost, c.baseline_score.continuity_cost
            )
        } else {
            format!(
                "**no** (`{:.4}` >= `{:.4}`); see *not better when* below",
                c.molt_score.continuity_cost, c.baseline_score.continuity_cost
            )
        };
        out.push_str(&format!(
            "Molt route ranks lower in continuity cost under these assumptions: {verdict}.\n\n"
        ));

        out.push_str("### Joins eliminated\n\n");
        if c.joins_eliminated.is_empty() {
            out.push_str("- (none)\n");
        } else {
            for j in &c.joins_eliminated {
                out.push_str(&render_join(j));
                out.push('\n');
            }
        }
        out.push_str("\n### Joins remaining (Molt route)\n\n");
        if c.molt_score.joins.is_empty() {
            out.push_str("- (none predicted by the scorer)\n");
        } else {
            for j in &c.molt_score.joins {
                out.push_str(&render_join(j));
                out.push('\n');
            }
        }
        for n in &b.joins_remaining_notes {
            out.push_str(&format!("- {n}\n"));
        }
        out.push_str(&format!("\n### Not better when\n\n{}\n", b.not_better_when));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::Field;

    fn fixtures_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    #[test]
    fn baselines_load_with_honesty_fields() {
        let baselines = load_baselines(&fixtures_dir().join("baselines")).expect("load");
        assert_eq!(baselines.len(), 5);
        for b in &baselines {
            assert!(!b.provenance.is_empty());
            assert!(!b.omitted.is_empty());
            assert!(!b.not_better_when.is_empty());
            assert!(!b.assumptions.treat_unknown_as_independent);
        }
        // titles sort A..E
        assert!(baselines[0].title.starts_with('A'));
        assert!(baselines[4].title.starts_with('E'));
    }

    #[test]
    fn baseline_rejects_dishonest_fixture() {
        let json = r#"{
            "name": "x", "title": "t", "summary": "s",
            "assumptions": {"colluding_set_size":1,"join_kinds":"AMOUNT","time_window_secs":1,"treat_unknown_as_independent":false},
            "provenance": "", "omitted": [], "not_better_when": "n", "molt_route": [],
            "manifest": {"adapter_id":"x","witnesses":[],"preserves":[],"latency_bound_secs":null}
        }"#;
        assert!(BaselineFixture::from_json(json).is_err());
        assert!(BaselineFixture::from_file(Path::new("/nonexistent.json")).is_err());
    }

    #[test]
    fn comparison_adapters_parse_and_chain() {
        let ads = comparison_adapters().expect("adapters");
        assert_eq!(ads.len(), 3);
        assert_eq!(ads[0].fixture().produces, ads[1].fixture().accepts);
        assert_eq!(ads[1].fixture().produces, ads[2].fixture().accepts);
    }

    #[test]
    fn every_comparison_plans_scores_and_ranks() {
        let baselines = load_baselines(&fixtures_dir().join("baselines")).expect("load");
        let declared = load_declared(&fixtures_dir().join("declared")).expect("declared");
        assert_eq!(declared.len(), 3);
        for b in &baselines {
            let c = run_comparison(b, &declared, &PRIVATE)
                .unwrap_or_else(|e| panic!("comparison {} failed: {e}", b.name));
            assert_eq!(c.molt_route.hops, b.molt_route);
            assert!(
                c.molt_score.continuity_cost < c.baseline_score.continuity_cost,
                "{}: molt {} !< baseline {}",
                b.name,
                c.molt_score.continuity_cost,
                c.baseline_score.continuity_cost
            );
            assert!(
                !c.joins_eliminated.is_empty(),
                "{}: expected some eliminated joins",
                b.name
            );
        }
    }

    #[test]
    fn render_is_deterministic() {
        let a = render_comparisons().expect("render");
        let b = render_comparisons().expect("render");
        assert_eq!(a, b);
        assert!(a.contains("Illustrative model fixtures, not empirical security benchmarks."));
    }

    #[test]
    fn declared_fixtures_match_s6() {
        let declared = load_declared(&fixtures_dir().join("declared")).expect("declared");
        let get = |id: &str| {
            declared
                .iter()
                .find(|d| d.id() == id)
                .expect(id)
                .fixture()
                .clone()
        };

        let ln = get("molt.declared.lightning_path");
        assert_eq!(ln.segments.opens.len(), 1);
        assert_eq!(ln.segments.opens[0].id.0, "ln");
        assert_eq!(
            ln.segments.closes,
            vec![crate::witness::SegmentId("ln".into())]
        );
        assert_eq!(ln.manifest.preserves.len(), 2);
        assert!(ln
            .manifest
            .preserves
            .iter()
            .any(|p| p.kind == Field::AMOUNT && p.namespace == "btc.sats"));
        assert!(ln
            .manifest
            .preserves
            .iter()
            .any(|p| p.kind == Field::TIME && p.namespace == "time.unix"));
        assert_eq!(ln.recovery, crate::route::RecoverySemantics::Atomic);
        assert_eq!(ln.produces.holder(), Holder::Counterparty);

        let swap = get("molt.declared.submarine_swap");
        assert_eq!(swap.segments.opens[0].id.0, "swap");
        assert_eq!(swap.produces.holder(), Holder::Self_);
        assert_eq!(
            swap.recovery,
            crate::route::RecoverySemantics::Refundable { window_secs: 3600 }
        );

        let bts = get("molt.declared.bounded_transfer_step");
        assert_eq!(bts.segments.opens[0].id.0, "step");
        assert!(bts.manifest.preserves.is_empty());
        assert_eq!(
            bts.recovery,
            crate::route::RecoverySemantics::BoundedAttributable {
                max_exposed_legs: 1
            }
        );
        assert_eq!(bts.produces.holder(), Holder::Counterparty);
        // No Chain, no Relay witnesses.
        assert!(bts.manifest.witnesses.iter().all(|w| !matches!(
            w.role,
            crate::witness::WitnessRole::Chain | crate::witness::WitnessRole::RelayOperator
        )));
    }
}
