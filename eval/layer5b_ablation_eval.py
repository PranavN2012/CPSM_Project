"""
Layer 5b Evaluation — Ablation Study (does blast radius's 35% weight matter?)
================================================================================
GROWTH_PLAN.md Phase 6 item 3. layer5_priority_scoring_eval.py already proved
the formula is *implemented* correctly (monotonicity, ranking). This script
asks a different question: does the specific 35% weight on blast radius (the
single largest of the four components) actually change real outcomes, or
would some other weighting have produced the same rankings anyway?

Methodology: re-scores the exact same 6 scenarios from
layer5_priority_scoring_eval.py (imported directly, not re-typed) twice —
once with the real, published weights, once with blast_radius's weight
zeroed out and redistributed evenly across the other three components (so
weights still sum to 1.0, keeping the comparison about *removing the blast-
radius signal specifically*, not about breaking the formula's normalization).
Reports the score/tier/rank delta for each scenario under both weightings.
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lambda", "shared"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ml.priority_scorer as priority_scorer
from ml.priority_scorer import PriorityScorer
from layer5_priority_scoring_eval import SCENARIOS

REAL_WEIGHTS = dict(priority_scorer.WEIGHTS)

# Redistribute blast_radius's 0.35 evenly across the other 3 (0.35/3 each),
# rather than just zeroing it without renormalizing — that would make the
# ablated weights sum to 0.65, which changes the score *scale*, not just
# removes the blast-radius *signal*. This isolates the one variable we want
# to test.
_redistribute = REAL_WEIGHTS["blast_radius"] / 3
ABLATED_WEIGHTS = {
    "anomaly": REAL_WEIGHTS["anomaly"] + _redistribute,
    "classification": REAL_WEIGHTS["classification"] + _redistribute,
    "blast_radius": 0.0,
    "recency": REAL_WEIGHTS["recency"] + _redistribute,
}


def _score_all(weights: dict) -> list:
    priority_scorer.WEIGHTS = weights
    scorer = PriorityScorer()
    results = []
    for name, kwargs, expected_tier in SCENARIOS:
        r = scorer.score(**kwargs)
        results.append((name, r.score, r.tier))
    return results


def main():
    print("=" * 90)
    print("LAYER 5b — Ablation: blast radius weight zeroed out (35% -> 0%, redistributed)")
    print("=" * 90)
    print(f"Real weights:    {REAL_WEIGHTS}")
    print(f"Ablated weights: { {k: round(v, 4) for k, v in ABLATED_WEIGHTS.items()} }")
    print()

    try:
        real_results = _score_all(REAL_WEIGHTS)
        ablated_results = _score_all(ABLATED_WEIGHTS)
    finally:
        priority_scorer.WEIGHTS = REAL_WEIGHTS  # always restore, even on failure

    real_by_name = {n: (s, t) for n, s, t in real_results}
    ablated_by_name = {n: (s, t) for n, s, t in ablated_results}

    real_rank = {n: i for i, (n, _, _) in enumerate(sorted(real_results, key=lambda x: -x[1]), 1)}
    ablated_rank = {n: i for i, (n, _, _) in enumerate(sorted(ablated_results, key=lambda x: -x[1]), 1)}

    print(f"{'Scenario':<32} {'Real score/tier':<20} {'Ablated score/tier':<20} {'Rank (real->ablated)'}")
    rows = []
    for name, _, _ in real_results:
        rs, rt = real_by_name[name]
        as_, at = ablated_by_name[name]
        rr, ar = real_rank[name], ablated_rank[name]
        rank_moved = rr != ar
        print(f"{name:<32} {f'{rs:.2f} {rt}':<20} {f'{as_:.2f} {at}':<20} {rr} -> {ar}"
              f"{'  (MOVED)' if rank_moved else ''}")
        rows.append({
            "name": name, "real_score": rs, "real_tier": rt, "real_rank": rr,
            "ablated_score": as_, "ablated_tier": at, "ablated_rank": ar,
            "rank_changed": rank_moved,
        })

    print()
    print("Specific check: 'unclassified_but_critical_blast' (classification confidence")
    print("0.0 but CRITICAL blast radius) vs. 'known_technique_low_impact' (confidence 0.9,")
    print("LOW blast radius) — does removing blast radius's weight flip their relative order?")
    a = ablated_by_name.get("unclassified_but_critical_blast")
    b = ablated_by_name.get("known_technique_low_impact")
    ra = real_by_name.get("unclassified_but_critical_blast")
    rb = real_by_name.get("known_technique_low_impact")
    if a and b:
        real_order_ok = ra[0] > rb[0]
        ablated_order_ok = a[0] > b[0]
        print(f"  Real weights:    unclassified_but_critical_blast ({ra[0]:.2f}) "
              f"{'>' if real_order_ok else '<='} known_technique_low_impact ({rb[0]:.2f}) "
              f"[{'as expected' if real_order_ok else 'UNEXPECTED'}]")
        print(f"  Ablated weights: unclassified_but_critical_blast ({a[0]:.2f}) "
              f"{'>' if ablated_order_ok else '<='} known_technique_low_impact ({b[0]:.2f}) "
              f"[{'still holds — ablation had no effect here' if ablated_order_ok else 'ORDER FLIPPED — blast radius weight was load-bearing for this pair'}]")

    tiers_changed = sum(1 for r in rows if r["real_tier"] != r["ablated_tier"])
    ranks_changed = sum(1 for r in rows if r["rank_changed"])
    print()
    print(f"Tiers changed by ablation:  {tiers_changed}/{len(rows)}")
    print(f"Ranks changed by ablation:  {ranks_changed}/{len(rows)}")

    out = {
        "layer": "5b", "name": "Ablation Study (blast radius weight)",
        "real_weights": REAL_WEIGHTS, "ablated_weights": ABLATED_WEIGHTS,
        "tiers_changed": tiers_changed, "ranks_changed": ranks_changed,
        "rows": rows,
    }
    return out


if __name__ == "__main__":
    result = main()
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_layer5b_ablation.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved -> {out_path}")
