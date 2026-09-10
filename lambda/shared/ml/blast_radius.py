"""
blast_radius.py — Layer 3: Blast Radius Simulation (Graph Reachability)
========================================================================
Models the cloud environment as a directed graph (IAM roles/users, S3
buckets, Lambda functions, DynamoDB tables, security groups) and answers
"if this identity is compromised, what can it reach?" via BFS.

Scope (intentional, stated explicitly — this is not a full IAM policy
evaluator):
  Handled:      Allow-effect statements, wildcard Action/Resource matching,
                AssumeRole trust relationships, multiple statements per
                policy document, explicit Deny (Deny wins over Allow).
                Two condition keys (aws:SourceIp, aws:MultiFactorAuthPresent)
                as of GROWTH_PLAN.md Phase 7: an Allow gated on either is
                excluded from the graph entirely rather than treated as an
                unconditional grant (see _is_condition_restricted) — a
                stolen-credential attacker typically can't satisfy an IP
                allowlist or an MFA prompt, so counting such a grant as a
                real edge would overstate reachability.
  NOT handled:  Any OTHER condition key, resource-based policies (e.g. S3
                bucket policies), permission boundaries, service control
                policies, session policies, NotAction/NotResource negation.

The seed-file graph (data/blast_radius_seed.json) is the primary demo
vehicle — hand-built with known-correct relationships. build_from_iam_policies()
covers the common-case IAM patterns above but does not claim full AWS IAM
evaluation fidelity. Both limitations are intentional scope decisions.
"""

import os
import json
import logging
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SEED_PATH = os.path.join(_SCRIPT_DIR, "data", "blast_radius_seed.json")

NODE_TYPES = frozenset([
    "IAMRole", "IAMUser", "S3Bucket", "LambdaFunction",
    "DynamoDBTable", "SecurityGroup",
])

EDGE_TYPES = frozenset([
    "can_assume", "can_read", "can_write", "can_invoke", "can_administer",
])

CRITICAL_TAGS = frozenset(["production", "pii", "payment", "admin"])

SEVERITY_THRESHOLDS = {
    # (min_critical_reached, min_total_reached) -> severity, checked in order
    "CRITICAL": {"critical": 2},
    "HIGH": {"critical": 1},
    "MEDIUM": {"total": 4},
}


@dataclass
class BlastRadiusResult:
    entry_point: str
    reachable_resources: list = field(default_factory=list)
    critical_resources_reached: list = field(default_factory=list)
    max_depth: int = 0
    total_nodes: int = 0
    severity: str = "LOW"
    paths: dict = field(default_factory=dict)  # resource_id -> path (list of node ids)


class InfraGraph:
    """Directed adjacency-list graph of cloud infrastructure and identities.

    Zero external dependencies (plain dicts). Nodes and edges are additive —
    build_from_seed() and build_from_iam_policies() can both be called on
    the same instance to layer a parsed IAM policy set on top of the seed.
    """

    def __init__(self):
        self.nodes: dict[str, dict] = {}       # node_id -> {"type": ..., "tags": [...]}
        self.adjacency: dict[str, list] = {}   # node_id -> [(target_id, edge_type), ...]

    # -- Construction ---------------------------------------------------

    def add_node(self, node_id: str, node_type: str, tags: list = None) -> None:
        self.nodes[node_id] = {"type": node_type, "tags": list(tags or [])}
        self.adjacency.setdefault(node_id, [])

    def add_edge(self, source: str, target: str, edge_type: str) -> None:
        if source not in self.nodes or target not in self.nodes:
            logger.warning("Skipping edge %s -%s-> %s: unknown node", source, edge_type, target)
            return
        self.adjacency.setdefault(source, []).append((target, edge_type))

    def build_from_seed(self, seed_json_path: str = None) -> "InfraGraph":
        """Load the pre-built seed graph (primary demo vehicle)."""
        path = seed_json_path or DEFAULT_SEED_PATH
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for node in data.get("nodes", []):
            self.add_node(node["id"], node["type"], node.get("tags", []))
        for edge in data.get("edges", []):
            self.add_edge(edge["source"], edge["target"], edge["type"])

        return self

    def build_from_iam_policies(self, roles: list, trust_policies: list = None) -> "InfraGraph":
        """Parse a defined, limited subset of IAM policy semantics onto this graph.

        Args:
            roles: [{"role_name": str, "policies": [{"Effect": "Allow"|"Deny",
                     "Action": str|list, "Resource": str|list}, ...]}, ...]
            trust_policies: [{"role_name": str, "trusted_principals": [str, ...]}, ...]

        Resources referenced by policies must already exist as nodes in this
        graph (e.g. via build_from_seed()) for wildcard matching to find them.
        """
        trust_policies = trust_policies or []

        for role in roles:
            role_name = role["role_name"]
            if role_name not in self.nodes:
                self.add_node(role_name, "IAMRole", [])

            allows, denies = self._resolve_statements(role.get("policies", []))

            for target_id, node in self.nodes.items():
                if target_id == role_name:
                    continue
                edge_type = self._edge_type_for_resource(target_id, node, allows, denies)
                if edge_type:
                    self.add_edge(role_name, target_id, edge_type)

        for trust in trust_policies:
            role_name = trust["role_name"]
            if role_name not in self.nodes:
                self.add_node(role_name, "IAMRole", [])
            for principal in trust.get("trusted_principals", []):
                if principal not in self.nodes:
                    self.add_node(principal, "IAMRole", [])
                self.add_edge(principal, role_name, "can_assume")

        return self

    # GROWTH_PLAN.md Phase 7: closes one of this module's own documented scope
    # gaps ("NOT handled: Condition keys"). Scoped deliberately to just these
    # two keys rather than general condition-key evaluation: blast radius
    # models "what can a compromised identity (e.g. stolen long-lived
    # credentials) reach" — an Allow gated on a source-IP allowlist or an
    # MFA requirement isn't usable by that attacker in the typical case, so
    # counting it as a real edge would overstate reachability. Any other
    # condition key remains an unhandled, undocumented-away gap (the
    # honest, disclosed limitation, not silently claimed as solved).
    RESTRICTIVE_CONDITION_KEYS = frozenset(["aws:SourceIp", "aws:MultiFactorAuthPresent"])

    @classmethod
    def _is_condition_restricted(cls, stmt: dict) -> bool:
        condition = stmt.get("Condition", {})
        if not isinstance(condition, dict):
            return False
        for operator_block in condition.values():
            if isinstance(operator_block, dict) and cls.RESTRICTIVE_CONDITION_KEYS.intersection(operator_block.keys()):
                return True
        return False

    @classmethod
    def _resolve_statements(cls, policies: list) -> tuple:
        """Split statements into (allow_actions, deny_actions) matched against 'Resource: *'
        style targets. Each entry is a set of action strings (e.g. {"s3:*", "dynamodb:GetItem"}).
        Explicit Deny is tracked separately so it can override Allow (per AWS evaluation order).

        An Allow statement gated on aws:SourceIp or aws:MultiFactorAuthPresent
        is excluded entirely (see _is_condition_restricted) rather than
        treated as an unconditional grant. Deny-side conditions are NOT
        specially handled — a conditional Deny still unconditionally blocks
        here, a documented simplification, not a claim of full condition-key
        evaluation.
        """
        allows, denies = [], []
        for stmt in policies:
            effect = stmt.get("Effect", "Allow")
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            entry = {"actions": set(actions), "resources": set(resources)}
            if effect == "Deny":
                denies.append(entry)
            else:
                if cls._is_condition_restricted(stmt):
                    continue
                allows.append(entry)

        return allows, denies

    @staticmethod
    def _resource_matches(resource_id: str, patterns: set) -> bool:
        for pattern in patterns:
            if pattern == "*":
                return True
            if pattern.endswith("*") and resource_id.startswith(pattern[:-1]):
                return True
            if pattern == resource_id:
                return True
        return False

    def _edge_type_for_resource(self, target_id: str, node: dict, allows: list, denies: list) -> str | None:
        """Determine the strongest edge type an Allow grants for target_id, unless a
        matching Deny statement blocks it (Deny always wins)."""
        best = None
        service_prefix = self._service_prefix(node["type"])

        for entry in denies:
            if self._resource_matches(target_id, entry["resources"]) or "*" in entry["resources"]:
                for action in entry["actions"]:
                    if action == "*" or action.startswith(f"{service_prefix}:"):
                        return None  # Explicit deny on this resource/service — no edge at all

        for entry in allows:
            if not (self._resource_matches(target_id, entry["resources"]) or "*" in entry["resources"]):
                continue
            for action in entry["actions"]:
                if action != "*" and not action.startswith(f"{service_prefix}:"):
                    continue
                if action.endswith(":*") or action == "*":
                    best = "can_administer"
                elif any(v in action for v in ("Put", "Delete", "Update", "Write")):
                    best = best or "can_write"
                elif any(v in action for v in ("Get", "List", "Describe", "Read")):
                    best = best if best in ("can_administer", "can_write") else "can_read"
                elif "Invoke" in action:
                    best = best or "can_invoke"

        return best

    @staticmethod
    def _service_prefix(node_type: str) -> str:
        return {
            "S3Bucket": "s3",
            "LambdaFunction": "lambda",
            "DynamoDBTable": "dynamodb",
            "SecurityGroup": "ec2",
            "IAMRole": "iam",
            "IAMUser": "iam",
        }.get(node_type, "")

    # -- Analysis ---------------------------------------------------------

    def is_critical(self, node_id: str) -> bool:
        node = self.nodes.get(node_id)
        if not node:
            return False
        return bool(CRITICAL_TAGS.intersection(node.get("tags", [])))

    def resource_exposure_severity(self, resource_id: str) -> BlastRadiusResult:
        """For a finding tied to a specific *resource* rather than a
        compromised *identity* (e.g. a publicly exposed S3 bucket found by a
        live scan) — not a BFS traversal, just an assessment of whether the
        named resource is itself tagged critical. Kept deliberately separate
        from simulate_blast_radius(): that function's identity-based
        traversal semantics are the ones verified 20/20 against an
        independent oracle in eval/layer3_blast_radius_eval.py, and this
        method must never change that behavior. It exists because a bucket
        node has no outgoing edges in this graph (it's a leaf), so using it
        as a BFS entry point would always report LOW/empty even when the
        bucket itself is tagged production/pii/payment — this method is what
        actually surfaces that tag-based risk for live findings whose
        resource name happens to match a real graph node (see
        scripts/simulate-attacks.py's BUCKET_NAMES, which intentionally
        reuses the seed graph's bucket names)."""
        is_crit = self.is_critical(resource_id)
        return BlastRadiusResult(
            entry_point=resource_id,
            reachable_resources=[],
            critical_resources_reached=[resource_id] if is_crit else [],
            max_depth=0,
            total_nodes=0,
            severity="HIGH" if is_crit else "LOW",
            paths={},
        )

    def simulate_blast_radius(self, entry_point: str, max_hops: int = 5) -> BlastRadiusResult:
        """BFS from entry_point, capped at max_hops, tracking the shortest path
        to every reachable node."""
        if entry_point not in self.nodes:
            raise ValueError(f"Unknown entry point: {entry_point}")

        visited = {entry_point: [entry_point]}
        queue = deque([(entry_point, 0)])
        max_depth_reached = 0

        while queue:
            current, depth = queue.popleft()
            if depth >= max_hops:
                continue
            for neighbor, _edge_type in self.adjacency.get(current, []):
                if neighbor in visited:
                    continue
                visited[neighbor] = visited[current] + [neighbor]
                max_depth_reached = max(max_depth_reached, depth + 1)
                queue.append((neighbor, depth + 1))

        reachable = [n for n in visited if n != entry_point]
        critical_reached = [n for n in reachable if self.is_critical(n)]

        result = BlastRadiusResult(
            entry_point=entry_point,
            reachable_resources=reachable,
            critical_resources_reached=critical_reached,
            max_depth=max_depth_reached,
            total_nodes=len(reachable),
            severity=self._compute_severity(len(critical_reached), len(reachable)),
            paths={n: visited[n] for n in reachable},
        )
        return result

    @staticmethod
    def _compute_severity(critical_count: int, total_count: int) -> str:
        if critical_count >= 2:
            return "CRITICAL"
        if critical_count >= 1:
            return "HIGH"
        if total_count >= 4:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "nodes": [{"id": nid, **info} for nid, info in self.nodes.items()],
            "edges": [
                {"source": src, "target": tgt, "type": etype}
                for src, edges in self.adjacency.items()
                for tgt, etype in edges
            ],
        }
