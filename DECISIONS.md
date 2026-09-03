# DECISIONS

Spec-ambiguity resolutions for the `pubky-molt` implementation of molt v10
sections S5, S6, S7, and S11. Each entry records the conservative reading
chosen and why. Section numbers refer to the v10 plan.

## Types and encoding

1. **`PurposeId` is defined locally.** S2 specifies `PurposeId` for
   `pubky-crypto`, but S6 (`RouteState::Custom`, `RouteConstraint::Custom`)
   needs it here and this crate may not depend on any Pubky crate. We define
   an equivalent `PurposeId` with the same grammar (`pubky.molt.<app>.v<N>`,
   lowercase ASCII `[a-z0-9_]`, `.`-separated, ≤ 64 bytes, validated on
   construction). `CorrelatorSpec.namespace` uses the relaxed
   "PurposeId-like" shape (no prefix/version requirement) because the spec's
   own examples (`lightning.payment_hash`, `btc.sats`) do not match the
   strict grammar.

2. **Fingerprint formula is spec-exact.**
   `BLAKE3("pubky-molt/fp/v1" || namespace || canonical_value)` with no
   length prefixing, exactly as S5 states. Namespaces are validated to the
   lowercase dotted grammar, so two different namespaces cannot collide into
   one prefix-free encoding except via the canonical value, which is what the
   spec intends.

3. **Deterministic CBOR.** `to_cbor()` on `CorrelatorSpec` (`{0: kind_bits,
   1: namespace}`), `Correlator` (`{0: spec, 1: fingerprint_bytes}`),
   `Segment` (`{0: id, 1: carries}`), and `Assumptions` (`{0..3}`). Integer
   map keys ascending, shortest-form integers, definite lengths (ciborium),
   per RFC 8949 §4.2. Only these types are byte-encoded anywhere in the
   crate; they are the objects vectors and traces compare.

4. **`Field` JSON form is the bitflags text form** (`"ROOT_IDENTITY |
   AMOUNT"`); the empty string decodes to the empty set (fixtures use it for
   a witness that learns nothing on one side). Non-human-readable encodings
   use raw `u32` bits.

## S5 — witnesses, domains, segments, detach

5. **`infra_provider` is unioned into an operator's known domains.** A
   shared infrastructure provider is a potential collusion path; ignoring it
   would overstate independence. Conservative.

6. **Unknown latency counts as inside the time window.** In `detach_level`
   (and the scorer's window logic), a missing `latency_bound_secs` is treated
   as within `time_window_secs`, i.e. AMOUNT/TIME count as leaks/joins.
   Treating unknown as outside the window would understate leaks.
   Conservative. Both `AMOUNT` and `TIME` are window-filtered ("AMOUNT/TIME
   count only within time_window").

7. **Open-segment leak exclusion matches on kind, then namespace.** A leak
   derived from domain visibility has no namespace; it is excluded if any
   open segment carries the same *kind*. A `preserves`-derived leak is
   excluded only when kind *and* namespace match a carried spec.

8. **`CollusionBounded(k)`** is the largest `k ≤ min(colluding_set_size,
   |known domains|)` such that no subset of known domains of size `2..=k`
   jointly observes a join-capable kind on both sides (size-1 subsets are
   already covered by the leak check). Subsets are enumerated exactly; domain
   counts in fixtures and tests are small, and `colluding_set_size` bounds
   the combinatorics.

9. **`SegmentEffects` apply opens → continues → closes within one hop.** v8
   requires an adapter to open and close a segment in a single hop
   (LightningPath); processing closes first would make that a
   `CloseWithoutOpen`.

10. **`continues` of a segment that is not open is reported as
    `CloseWithoutOpen`.** The spec's `RejectReason` has no dedicated variant;
    it is the same bookkeeping error class.

11. **`DuplicateSegmentId`** fires when a hop opens an id that is currently
    open *or was used anywhere earlier on the route*. Re-opening a closed id
    would make `open_segments_at` history ambiguous.

## S6 — planner

12. **`plan()` checks boundary segment violations with an empty
    `DomainRegistry` and default `Assumptions`.** The `plan` signature
    carries neither, and only the violation arm of `detach_level` (open
    segment carries ⊆ previous hop's preserves) is relevant to planning;
    detach *levels* are the scorer's business.

13. **Cycles are dropped, not recorded as rejections.** `RejectReason` has
    no cycle variant; a candidate that would revisit a state is simply never
    queued.

14. **A produced state equal to the goal is accepted regardless of
    `Holder`.** A payment ends at the receiver (Counterparty-held). Any
    non-goal state not held by `Self_` ends the branch with
    `HolderNotSelf`, and the rejection is returned, per spec.

15. **`from == to` yields the trivial empty route.**

16. **`max_routes` caps discovery.** The bounded BFS stops extending once
    `max_routes` complete routes are found; earlier (shallower) routes win by
    BFS order.

17. **Deferred constraints** (`RequiresSuccessor`, successor side of
    `ExclusiveAdjacency`) are checked when the next hop is added, and again
    at finalization for a trailing hop. `NotRepeatable` and
    `RequiresPredecessor` are checked at insertion. `Custom` with no
    registered evaluator is `UnsupportedConstraint` (fail closed); with an
    evaluator, `holds(rule, route, at_hop)` decides.

## S7 — scorer

18. **Observation points.** Point 0 is hop 0's input, point `p` (1..n) the
    boundary between hops `p−1` and `p` (union of the left hop's `learns_out`
    and the right hop's `learns_in`), point `n` the last hop's output. Joins
    are enumerated per (minimal domain set, point pair). `JoinReport.joins`
    is a `Vec` so one report can carry multiple point pairs.

19. **`detaches[i]` is hop `i`'s own in→out crossing**, computed as
    `detach_level(m_i, m_i, continuing_segments)`. Internal composition
    boundaries are checked for `SegmentViolation` only. A hop that continues
    a segment must preserve its carries; a hop that merely opens+closes a
    segment internally (LightningPath) has nothing checked against its
    `preserves`, matching the spec's "the hash does not cross past the
    close".

20. **One join, one severity: the max over `via` kinds.** The spec's
    formula applies `severity(via.kind)` per join; summing per kind would
    double-count a single join. Confidence is likewise the max over the via
    kinds. Confidence rule: value-continuous (preserved at every hop between
    the points) identifier kinds ⇒ `Exact`; value-continuous AMOUNT/TIME/
    DENOMINATION within the window ⇒ `High`; everything else ⇒
    `Statistical`. TIME/AMOUNT joins outside the window are still reported at
    `Statistical` rather than dropped (the scorer reports; `detach_level`
    filters).

21. **Witnesses with no known domain contribute no scored joins** (their
    uncertainty is already reported as `DetachLevel::Unknown`, which earns a
    smaller detach bonus than `Independent`). Attributing them to a synthetic
    "unknown" domain would fabricate joins the data does not support.

22. **Constants** (spec orders but does not assign numbers): severity
    `ROOT_IDENTITY=100 ≫ RELATIONSHIP_IDENTITY=25 ≫ PAIRWISE_KEY=20 ≫
    identifier kinds=10 > AMOUNT|TIME|DENOMINATION=5 > RELATIONSHIP_LINK=2 >
    other=1`; `c(Exact)=1.0, c(High)=0.8, c(Statistical)=0.3` (spec-given);
    `w(|S|)=1/|S|`; detach bonus `None=0, Unknown=0.1, Independent=1.0,
    CollusionBounded(k)=1.0+0.5k`. All recorded in
    `tests/vectors/molt_route_v1.json` and pinned by tests.

23. **`Weights` presets** (spec gives names only): `FAST=(0.2, 0.3, 0.5)`,
    `CHEAP=(0.2, 0.6, 0.2)`, `PRIVATE=(0.7, 0.2, 0.1)`,
    `MAX_DETACH=(1.0, 0.0, 0.0)` — each summing to 1.

24. **`continuity_cost` is clamped at 0 and stored scaled by
    `w.continuity`** so `RouteScore` values from different presets are
    comparable preference numbers; `RouteScore::total(w)` adds the
    `w.cost · reduced_cost + w.latency · latency` terms. Invalid (negative,
    non-finite) weights are rejected with `ScoreError::Cost`.

25. **A hop with no matching adapter in `score()`** is reported as
    `Unplannable(UnsupportedConstraint { namespace: pubky.molt.score.v1,
    adapter })` — the least-wrong spec variant; callers are expected to pass
    the same adapters used to plan. Structurally inconsistent routes (bad
    lengths, trailing open segment) are `Unplannable(_)`.

## S11 — fixtures and comparisons

26. **Fixture `assumptions` use `colluding_set_size = 1`**, matching the v1
    threat model (S0 protects against *non-colluding* operators). Larger
    colluding sets are exercised by unit tests and supported everywhere.

27. **The comparison `SumAll` cost policy is illustrative**: it sums quoted
    values across assets so `score()` can run; the rendered document reports
    continuity cost, joins, and detaches — never cross-asset totals. Real
    callers supply a real `CostPolicy` (e.g. `SingleAsset`).

28. **The embedded comparison adapters** (`molt.intro.session`,
    `molt.drop.channel`, `molt.payment.intent`) are declared data: their
    manifests mirror S8/S9 honestly; their *state chaining* is illustrative
    (the executing adapters live in paykit-rs, S9). `molt.payment.intent`
    models local application intent crossing no network, hence an empty
    witness list.

29. **Fixture loaders ignore `._*` AppleDouble sidecar files** (some
    filesystems create them next to every file); they are metadata junk, not
    fixtures.

30. **`docs/COMPARISONS.md` is regenerated only under
    `MOLT_COMPARISONS_REGENERATE=1 cargo test --doc`**; the default doc-test
    path fails on any drift from the committed file.
