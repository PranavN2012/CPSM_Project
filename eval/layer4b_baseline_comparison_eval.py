"""
Layer 4b Evaluation — Baseline Comparison (single-shot vs. propose-test-revise)
=================================================================================
GROWTH_PLAN.md Phase 6 item 2: the one number layer4_policy_drafting_eval.py's
own "Honest caveat" flagged as missing — layer4_policy_drafting_eval.py proved
the propose-test-revise loop achieves 100% pass within 3 attempts, but never
measured what a naive single-shot LLM call (no sandbox-test-revise loop)
would have achieved on the exact same scenarios. Without that number, "the
loop helps" was a plausible claim, not a measured one.

Methodology: runs the SAME 12 scenarios (imported directly from
layer4_policy_drafting_eval.py, not re-typed, so there's no chance of the two
sets silently drifting apart) through PolicyAgent.draft_fix() called exactly
ONCE per scenario (attempt 1, no revision), then independently verifies each
draft with a fresh PolicyEvaluator — the same independent-verification
discipline the main Layer 4 eval used, so a "pass" here means the same thing
a "pass" means there. This isolates one variable: does the test-and-revise
loop itself account for the difference, holding the LLM and scenarios fixed?
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lambda", "shared"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.policy_agent import PolicyAgent
from layer4_policy_drafting_eval import SCENARIOS, independently_verify


def main():
    agent = PolicyAgent()
    client_name = agent.llm_client.__class__.__name__
    print("=" * 90)
    print(f"LAYER 4b — Baseline Comparison: single-shot LLM draft, no test-revise loop (LLM: {client_name})")
    print("=" * 90)
    print(f"Running the same {len(SCENARIOS)} scenarios through ONE draft_fix() call each (attempt 1 only)...")
    print()

    rows = []
    for i, scenario in enumerate(SCENARIOS, 1):
        incident = {
            "current_policy": scenario["current_policy"],
            "offending_action": scenario["offending_action"],
            "offending_resource": scenario["offending_resource"],
            "must_still_allow": scenario["must_still_allow"],
        }
        print(f"[{i}/{len(SCENARIOS)}] {scenario['name']} ...", flush=True)

        # The single-shot baseline: exactly one draft_fix() call, no test_fix()
        # feedback loop, no retry — this is what "just ask the LLM once" looks
        # like, as opposed to PolicyAgent.revise_and_retry()'s full loop.
        draft = agent.draft_fix(incident, blast_radius={})

        narrowed, preserved = independently_verify(
            draft.policy_json, scenario["offending_action"], scenario["offending_resource"],
            scenario["must_still_allow"],
        )
        passed = narrowed and preserved
        rows.append({"name": scenario["name"], "single_shot_passed": passed,
                     "narrowed": narrowed, "preserved_required": preserved})

    n = len(SCENARIOS)
    single_shot_pass = sum(1 for r in rows if r["single_shot_passed"])

    print()
    for r in rows:
        print(f"  [{'PASS' if r['single_shot_passed'] else 'FAIL'}] {r['name']:<38} "
              f"narrowed={r['narrowed']}  preserved_required={r['preserved_required']}")

    print()
    print(f"Single-shot pass rate:                  {single_shot_pass}/{n} ({100*single_shot_pass/n:.0f}%)")
    print(f"Propose-test-revise pass rate (attempt 1, from layer4_policy_drafting_eval.py): "
          f"see results_layer4.json's pct_pass_attempt_1")
    print(f"Propose-test-revise pass rate (within 3 attempts): see results_layer4.json's pct_pass_within_3")
    print()
    print("Interpretation: any gap between the single-shot number above and the")
    print("propose-test-revise 'within 3 attempts' number is the loop's measured")
    print("contribution — not asserted, read directly off both result files.")

    out = {
        "layer": "4b", "name": "Baseline Comparison (single-shot vs. propose-test-revise)",
        "llm_client": client_name, "n_scenarios": n,
        "pct_single_shot_pass": round(100 * single_shot_pass / n, 1),
        "rows": rows,
    }
    return out


if __name__ == "__main__":
    result = main()
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_layer4b_baseline.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved -> {out_path}")
