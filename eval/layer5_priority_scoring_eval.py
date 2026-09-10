"""
Layer 5 Evaluation — Priority Scoring
========================================
Not an ML-accuracy problem — PriorityScorer is a fixed weighted formula
(see priority_scorer.py: 25% anomaly, 20% classification confidence, 35%
blast radius, 20% recency). What's worth verifying is:

  1. Monotonicity: increasing any single component, holding the others
     fixed, must never decrease the composite score. If it did, the
     formula would be internally inconsistent (e.g. a MORE anomalous
     event scoring lower priority than a less anomalous one, all else
     equal) — a real correctness bug, not just a modeling choice.

  2. Ranking consistency against manually-defined ground-truth scenarios:
     a CRITICAL + highly anomalous + recent scenario must outrank a LOW +
     normal + old one, and a full spread of scenarios in between must sort
     into the expected relative order and land in the expected P1-P4 tier.

Note on the expected tiers below: this is a fully deterministic, published
linear formula (25/20/35/20 weights, documented severity/recency mappings,
fixed tier thresholds) — there's no ambiguity to resolve by running the code
and seeing what comes out, the way there was for Layer 2's ATT&CK ground
truth. The expected tiers were computed by hand from the documented formula
before running this script; three of the first-pass guesses turned out to
be arithmetic mistakes on the reviewer's part (e.g. mentally rounding 44.25
down to "should be P4" when the formula's own P3 threshold is 40, not 45) —
caught and corrected against the formula itself, not against whatever the
code happened to output.
"""

import sys
import os
import json
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lambda", "shared"))

from ml.priority_scorer import PriorityScorer

scorer = PriorityScorer()
NOW = datetime.now(timezone.utc)


def recent_history(n=3):
    return [{"pattern_key": "TX", "timestamp": NOW.isoformat()} for _ in range(n)]


def old_history():
    return [{"pattern_key": "TX", "timestamp": (NOW - timedelta(days=60)).isoformat()}]


# ---------------------------------------------------------------------------
# 1. Monotonicity checks
# ---------------------------------------------------------------------------

def check_monotonicity():
    print("=" * 80)
    print("Monotonicity checks (raising one component must never lower the score)")
    print("=" * 80)
    baseline = dict(anomaly_score=0.5, classification_confidence=0.5,
                     blast_radius_severity="MEDIUM", pattern_key="TX", history=[])

    checks = []

    lo = scorer.score(**{**baseline, "anomaly_score": 0.1}).score
    hi = scorer.score(**{**baseline, "anomaly_score": 0.9}).score
    checks.append(("anomaly_score 0.1 -> 0.9", lo, hi, hi >= lo))

    lo = scorer.score(**{**baseline, "classification_confidence": 0.1}).score
    hi = scorer.score(**{**baseline, "classification_confidence": 0.9}).score
    checks.append(("classification_confidence 0.1 -> 0.9", lo, hi, hi >= lo))

    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for a, b in zip(severities, severities[1:]):
        lo = scorer.score(**{**baseline, "blast_radius_severity": a}).score
        hi = scorer.score(**{**baseline, "blast_radius_severity": b}).score
        checks.append((f"blast_radius {a} -> {b}", lo, hi, hi >= lo))

    lo = scorer.score(**{**baseline, "history": old_history()}).score
    hi = scorer.score(**{**baseline, "history": recent_history()}).score
    checks.append(("recency: old-only history -> 3x recent history", lo, hi, hi >= lo))

    all_ok = True
    for name, lo, hi, ok in checks:
        all_ok = all_ok and ok
        print(f"  [{'OK' if ok else 'FAIL'}] {name:<45} {lo:>6.2f} -> {hi:>6.2f}")
    print()
    return all_ok


# ---------------------------------------------------------------------------
# 2. Manually-defined ground-truth ranking scenarios
# ---------------------------------------------------------------------------

SCENARIOS = [
    ("critical_anomalous_recent", dict(anomaly_score=0.95, classification_confidence=0.9,
                                        blast_radius_severity="CRITICAL", pattern_key="T1078",
                                        history=recent_history()), "P1"),
    ("high_confident_recent", dict(anomaly_score=0.75, classification_confidence=0.8,
                                    blast_radius_severity="HIGH", pattern_key="T1098",
                                    history=recent_history()), "P2"),
    ("medium_moderate_novel", dict(anomaly_score=0.5, classification_confidence=0.5,
                                    blast_radius_severity="MEDIUM", pattern_key="T1526",
                                    history=[]), "P3"),
    ("low_normal_old", dict(anomaly_score=0.1, classification_confidence=0.1,
                             blast_radius_severity="LOW", pattern_key="T9999",
                             history=old_history()), "P4"),
    ("unclassified_but_critical_blast", dict(anomaly_score=0.6, classification_confidence=0.0,
                                              blast_radius_severity="CRITICAL", pattern_key="",
                                              history=[]), "P2"),
    ("known_technique_low_impact", dict(anomaly_score=0.3, classification_confidence=0.9,
                                         blast_radius_severity="LOW", pattern_key="T1526",
                                         history=[]), "P3"),
]


def check_ranking():
    print("=" * 80)
    print("Manually-defined ground-truth scenarios — score, tier, and expected tier")
    print("=" * 80)
    results = []
    for name, kwargs, expected_tier in SCENARIOS:
        r = scorer.score(**kwargs)
        results.append((name, r.score, r.tier, expected_tier))

    all_ok = True
    for name, score, tier, expected in results:
        ok = tier == expected
        all_ok = all_ok and ok
        print(f"  [{'OK' if ok else 'FAIL'}] {name:<32} score={score:>6.2f}  tier={tier}  (expected {expected})")

    print()
    print("Pairwise ranking check: critical_anomalous_recent must outrank low_normal_old")
    crit_score = next(s for n, s, t, e in results if n == "critical_anomalous_recent")
    low_score = next(s for n, s, t, e in results if n == "low_normal_old")
    rank_ok = crit_score > low_score
    print(f"  [{'OK' if rank_ok else 'FAIL'}] {crit_score:.2f} > {low_score:.2f}: {rank_ok}")

    print()
    print("Full ranking (descending) — sanity check the ordering reads as intuitively expected:")
    for name, score, tier, expected in sorted(results, key=lambda x: -x[1]):
        print(f"  {score:>6.2f}  {tier}  {name}")

    return all_ok and rank_ok, results


def main():
    mono_ok = check_monotonicity()
    rank_ok, results = check_ranking()

    out = {
        "layer": 5, "name": "Priority Scoring",
        "monotonicity_all_passed": mono_ok,
        "ranking_all_passed": rank_ok,
        "scenarios": [{"name": n, "score": s, "tier": t, "expected_tier": e} for n, s, t, e in results],
    }
    print()
    print(f"Overall: monotonicity {'PASS' if mono_ok else 'FAIL'}, ranking {'PASS' if rank_ok else 'FAIL'}")
    return out


if __name__ == "__main__":
    result = main()
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_layer5.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved -> {out_path}")
