"""
run_benchmark.py — Universal Security Generalization Benchmark, pilot scale.

Runs scenarios.py's 24 blind Halcyon-Corp scenarios through the REAL
ThreatOrchestrator (real Groq LLM, real Layer 1-5 pipeline), scores each
against ground_truth.py's independently-authored expectations, and produces
both a per-case JSON dump (schema close to the brief's Section 13) and the
headline metrics from Sections 7-8.

Usage: python eval/generalization_benchmark/run_benchmark.py
"""

import sys
import os
import json
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "lambda", "shared"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.orchestrator import ThreatOrchestrator
from ml.policy_agent import PolicyEvaluator
from halcyon_graph import build_halcyon_graph
from scenarios import SCENARIOS, FAMILIES
from ground_truth import GROUND_TRUTH


def _access_ok(evaluator, policy_json, pair):
    action, resource = pair
    return evaluator.evaluate(policy_json, action, resource)


def _score_decision(actual_decision: str, expected) -> bool:
    if expected == "no_crash":
        return True  # crash-vs-not is checked separately
    expected_set = expected if isinstance(expected, list) else [expected]
    return actual_decision in expected_set


def _score_technique(actual_technique: str, expected) -> bool:
    if isinstance(expected, str) and expected.startswith("N/A"):
        return True  # not applicable — don't penalize
    expected_set = expected if isinstance(expected, list) else [expected]
    return actual_technique in expected_set


def _score_blast_radius(actual_severity: str, expected: str) -> bool:
    if expected.startswith("N/A"):
        return True
    # "LOW (...)" style annotations — compare only the leading token.
    expected_token = expected.split()[0]
    return actual_severity == expected_token


def run_one(orchestrator: ThreatOrchestrator, evaluator: PolicyEvaluator, scenario: dict) -> dict:
    scenario_id = scenario["scenario_id"]
    event = scenario["event"]
    gt = GROUND_TRUTH[scenario_id]

    result = {
        "scenario_id": scenario_id, "family": scenario["family"], "trap": scenario["trap"],
        "note": scenario.get("note", ""), "input": event, "ground_truth": gt,
        "model_output": {}, "verification": {}, "scoring": {}, "crashed": False, "error": None,
    }

    try:
        pipeline_result = orchestrator.process_event(dict(event))
    except Exception as exc:
        result["crashed"] = True
        result["error"] = f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"
        return result

    technique = pipeline_result.classification.technique_id if pipeline_result.classification else None
    blast_severity = pipeline_result.blast_radius.severity if pipeline_result.blast_radius else None

    result["model_output"] = {
        "anomaly": pipeline_result.is_anomalous,
        "anomaly_score": pipeline_result.anomaly_score,
        "technique": technique,
        "blast_radius": blast_severity,
        "decision": pipeline_result.decision,
        "rationale": pipeline_result.rationale,
    }

    scoring = {}

    # Anomaly: only score strictly when ground truth is a clean True/False;
    # "borderline" and None (GB-24, robustness-only) are recorded but not
    # forced into a pass/fail — that would fabricate precision GT doesn't have.
    gt_anomaly = gt["anomaly"]
    if isinstance(gt_anomaly, bool):
        scoring["anomaly_correct"] = (pipeline_result.is_anomalous == gt_anomaly)
        scoring["anomaly_scorable"] = True
    else:
        scoring["anomaly_correct"] = None
        scoring["anomaly_scorable"] = False

    scoring["technique_correct"] = _score_technique(technique, gt["technique"]) if pipeline_result.is_anomalous else True
    scoring["blast_radius_correct"] = _score_blast_radius(blast_severity, gt["blast_radius"]) if pipeline_result.is_anomalous else True
    scoring["decision_correct"] = _score_decision(pipeline_result.decision, gt["decision"])

    # Remediation safety — independent re-verification, not trusting the
    # draft's own test_passed flag (same discipline as layer4_policy_drafting_eval.py).
    if pipeline_result.policy_draft is not None:
        draft = pipeline_result.policy_draft
        offending = event.get("policy_fix_context", {})
        forbidden_ok = all(
            not _access_ok(evaluator, draft.policy_json, pair)
            for pair in gt.get("forbidden_access", [[offending.get("offending_action"), offending.get("offending_resource")]])
            if pair[0] is not None
        )
        required_ok = all(
            _access_ok(evaluator, draft.policy_json, pair)
            for pair in gt.get("required_access", [])
        )
        result["verification"] = {
            "policy_valid": isinstance(draft.policy_json, dict) and bool(draft.policy_json.get("Statement") is not None),
            "vulnerability_removed": forbidden_ok,
            "required_access_preserved": required_ok,
            "safe_fix": forbidden_ok and required_ok,
            "agent_reported_test_passed": draft.test_passed,
        }
        scoring["remediation_safe"] = forbidden_ok and required_ok

    result["scoring"] = scoring
    return result


def main():
    graph = build_halcyon_graph()
    orchestrator = ThreatOrchestrator(infra_graph=graph)
    evaluator = PolicyEvaluator()

    print("=" * 90)
    print(f"UNIVERSAL SECURITY GENERALIZATION BENCHMARK — pilot scale "
          f"({len(SCENARIOS)} scenarios, target 120-150)")
    print(f"LLM: {orchestrator.policy_agent.llm_client.__class__.__name__} | "
          f"Reasoner: {orchestrator.reasoner.__class__.__name__}")
    print("=" * 90)

    all_results = []
    for i, scenario in enumerate(SCENARIOS, 1):
        print(f"[{i}/{len(SCENARIOS)}] {scenario['scenario_id']} ({scenario['family']}"
              f"{', TRAP' if scenario['trap'] else ''}) ...", flush=True)
        r = run_one(orchestrator, evaluator, scenario)
        all_results.append(r)
        if r["crashed"]:
            print(f"    !! CRASHED: {r['error'].splitlines()[0]}")
        else:
            mo = r["model_output"]
            print(f"    anomaly={mo['anomaly']} ({mo['anomaly_score']:.3f})  technique={mo['technique']}  "
                  f"blast={mo['blast_radius']}  decision={mo['decision']}")

    out_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(out_dir, "results.json"), "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nSaved per-case results -> {os.path.join(out_dir, 'results.json')}")

    return all_results


if __name__ == "__main__":
    main()
