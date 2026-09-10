"""
run_all.py — Runs all 5 layer evaluations in sequence and prints a
consolidated summary. Each layer script also writes its own
eval/results_layer{N}.json for detailed inspection.

Note: Layer 4 makes real LLM API calls (whichever provider is configured via
.env — Groq preferred) and takes noticeably longer than the others (~1-2 min
for 12 scenarios) as a result.

Usage: python eval/run_all.py
"""

import subprocess
import sys
import os
import json

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = [
    "layer1_anomaly_eval.py",
    "layer2_attack_classification_eval.py",
    "layer3_blast_radius_eval.py",
    "layer4_policy_drafting_eval.py",
    "layer4b_baseline_comparison_eval.py",
    "layer5_priority_scoring_eval.py",
    "layer5b_ablation_eval.py",
]


def main():
    for script in SCRIPTS:
        path = os.path.join(EVAL_DIR, script)
        print(f"\n{'#' * 90}\n# Running {script}\n{'#' * 90}\n")
        subprocess.run([sys.executable, path], check=True)

    print(f"\n{'=' * 90}\nCONSOLIDATED SUMMARY\n{'=' * 90}")
    result_files = [
        "results_layer1.json", "results_layer2.json", "results_layer3.json",
        "results_layer4.json", "results_layer4b_baseline.json",
        "results_layer5.json", "results_layer5b_ablation.json",
    ]
    for fname in result_files:
        result_path = os.path.join(EVAL_DIR, fname)
        if not os.path.exists(result_path):
            continue
        with open(result_path) as f:
            r = json.load(f)
        print(f"\nLayer {r.get('layer', '?')} — {r['name']}")
        for k, v in r.items():
            if k in ("layer", "name", "rows", "scenarios", "confusion_matrix"):
                continue
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
