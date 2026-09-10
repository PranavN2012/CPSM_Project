"""
Layer 3 Evaluation — Blast Radius (Graph Reachability)
=========================================================
Layer 3 is deterministic graph BFS, not ML — "ground truth" here means an
INDEPENDENT re-implementation of reachability + severity, built with a
different library (networkx) and a different traversal style, cross-checked
against InfraGraph's own BFS for every node in the real seed graph
(lambda/shared/ml/data/blast_radius_seed.json). A hand-traced-by-eye "let me
manually walk the graph" ground truth is exactly the kind of thing a human
gets subtly wrong on a 20-node graph; an independently-coded oracle is not.

For each entry point, checks:
  - the exact reachable-node set
  - severity (CRITICAL/HIGH/MEDIUM/LOW, per InfraGraph's own thresholds:
    >=2 critical-tagged nodes reached -> CRITICAL, >=1 -> HIGH, >=4 total
    reached -> MEDIUM, else LOW)
  - max_depth reached

Also includes three specific "known chain" assertions matching the
CRITICAL_TAGS-tagged nodes in the seed graph, e.g. dev-intern-role's
documented ability to assume ci-deploy-role (an admin-tagged role) and reach
production/PII-tagged buckets from there — the exact scenario the
Dashboard/AI-Insights demo relies on to show a meaningful CRITICAL result.
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lambda", "shared"))

import networkx as nx
from ml.blast_radius import InfraGraph, CRITICAL_TAGS


def build_networkx_oracle(seed_path):
    with open(seed_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    g = nx.DiGraph()
    tags_by_node = {}
    for node in data["nodes"]:
        g.add_node(node["id"])
        tags_by_node[node["id"]] = set(node.get("tags", []))
    for edge in data["edges"]:
        g.add_edge(edge["source"], edge["target"])

    return g, tags_by_node


def oracle_blast_radius(g, tags_by_node, entry, max_hops=5):
    """Independent BFS via networkx.single_source_shortest_path_length,
    then hand-applies the exact same severity rule InfraGraph documents,
    re-derived from scratch rather than imported."""
    lengths = nx.single_source_shortest_path_length(g, entry, cutoff=max_hops)
    reachable = [n for n, d in lengths.items() if n != entry]
    max_depth = max((d for n, d in lengths.items() if n != entry), default=0)
    critical_reached = [n for n in reachable if tags_by_node.get(n, set()) & CRITICAL_TAGS]

    if len(critical_reached) >= 2:
        severity = "CRITICAL"
    elif len(critical_reached) >= 1:
        severity = "HIGH"
    elif len(reachable) >= 4:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return set(reachable), severity, max_depth, set(critical_reached)


def main():
    seed_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                              "lambda", "shared", "ml", "data", "blast_radius_seed.json")
    seed_path = os.path.normpath(seed_path)

    graph = InfraGraph().build_from_seed(seed_path)
    nx_graph, tags_by_node = build_networkx_oracle(seed_path)

    print("=" * 80)
    print("LAYER 3 — Blast Radius Evaluation (InfraGraph BFS vs. independent networkx oracle)")
    print("=" * 80)
    print(f"Graph: {len(graph.nodes)} nodes, "
          f"{sum(len(v) for v in graph.adjacency.values())} edges")
    print()

    mismatches = []
    rows = []
    for entry in sorted(graph.nodes.keys()):
        actual = graph.simulate_blast_radius(entry)
        expected_reachable, expected_severity, expected_depth, expected_critical = oracle_blast_radius(
            nx_graph, tags_by_node, entry
        )

        reachable_match = set(actual.reachable_resources) == expected_reachable
        severity_match = actual.severity == expected_severity
        depth_match = actual.max_depth == expected_depth
        ok = reachable_match and severity_match and depth_match

        rows.append((entry, actual, expected_reachable, expected_severity, expected_depth, ok))
        if not ok:
            mismatches.append(entry)

    for entry, actual, expected_reachable, expected_severity, expected_depth, ok in rows:
        mark = "OK" if ok else "MISMATCH"
        print(f"[{mark:8}] {entry:<26} reachable={len(actual.reachable_resources):>2} "
              f"(expected {len(expected_reachable):>2})  severity={actual.severity:<8} "
              f"(expected {expected_severity:<8})  max_depth={actual.max_depth} (expected {expected_depth})")
        if not ok:
            print(f"             actual reachable:   {sorted(actual.reachable_resources)}")
            print(f"             expected reachable: {sorted(expected_reachable)}")

    print()
    print(f"{len(rows) - len(mismatches)}/{len(rows)} entry points match the independent oracle exactly.")

    # -- Known-chain spot checks (the ones the demo/UI actually relies on) --
    print()
    print("Known-chain spot checks:")
    checks = [
        ("dev-intern-role", "ci-deploy-role", "can assume the admin-tagged deploy role"),
        ("dev-intern-role", "prod-data-lake-raw", "reaches a production/PII bucket via the assumed role"),
        ("dev-intern-role", "customer-reports-q1", "reaches a production/PII/payment bucket via the assumed role"),
        ("backup-service-role", "session-tokens-table", "reads the session-tokens table directly"),
        ("analyst-user", "ml-training-datasets", "reads ML training data directly"),
    ]
    all_chain_ok = True
    for entry, target, description in checks:
        result = graph.simulate_blast_radius(entry)
        ok = target in result.reachable_resources
        all_chain_ok = all_chain_ok and ok
        print(f"  [{'OK' if ok else 'FAIL'}] {entry} -> {target}: {description}")

    dev_intern_result = graph.simulate_blast_radius("dev-intern-role")
    severity_ok = dev_intern_result.severity == "CRITICAL"
    print(f"  [{'OK' if severity_ok else 'FAIL'}] dev-intern-role overall severity = "
          f"{dev_intern_result.severity} (expected CRITICAL — this is the pipeline's headline "
          f"'low-privilege identity escalates to admin' demo scenario)")

    out = {
        "layer": 3, "name": "Blast Radius",
        "n_entry_points": len(rows),
        "n_matching_oracle": len(rows) - len(mismatches),
        "mismatches": mismatches,
        "known_chain_checks_passed": all_chain_ok and severity_ok,
    }
    return out


if __name__ == "__main__":
    result = main()
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_layer3.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved -> {out_path}")
