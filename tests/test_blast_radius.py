"""
test_blast_radius.py — Tests for Layer 3: Blast Radius Simulation
===================================================================
Covers seed-graph loading, BFS reachability/depth limits, severity
scoring, and the scoped IAM policy parser (Allow/Deny/wildcards).
"""

import sys
import os

import pytest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
sys.path.insert(0, os.path.join(PROJECT_DIR, "lambda", "shared"))

from ml.blast_radius import InfraGraph, BlastRadiusResult, DEFAULT_SEED_PATH


# ---------------------------------------------------------------------------
# Seed graph loading
# ---------------------------------------------------------------------------

class TestSeedLoading:
    def test_loads_default_seed(self):
        graph = InfraGraph().build_from_seed()
        assert "dev-intern-role" in graph.nodes
        assert "prod-data-lake-raw" in graph.nodes
        assert graph.nodes["prod-data-lake-raw"]["type"] == "S3Bucket"

    def test_critical_tags_loaded(self):
        graph = InfraGraph().build_from_seed()
        assert graph.is_critical("prod-data-lake-raw")
        assert graph.is_critical("customer-reports-q1")
        assert not graph.is_critical("dev-user-uploads")

    def test_edges_loaded(self):
        graph = InfraGraph().build_from_seed()
        targets = {t for t, _ in graph.adjacency["dev-intern-role"]}
        assert "ci-deploy-role" in targets


# ---------------------------------------------------------------------------
# BFS reachability
# ---------------------------------------------------------------------------

class TestBlastRadiusBFS:
    def test_dev_intern_role_limited_blast_radius(self):
        """At 1 hop, a low-privilege role should NOT reach production S3 buckets
        directly — it only reaches its own resources plus the admin role it can
        assume (which itself is flagged critical, hence HIGH here)."""
        graph = InfraGraph().build_from_seed()
        result = graph.simulate_blast_radius("dev-intern-role", max_hops=1)

        assert "prod-data-lake-raw" not in result.reachable_resources
        assert "dev-user-uploads" in result.reachable_resources
        assert result.severity == "HIGH"

    def test_dev_intern_role_full_blast_radius_via_assume_role(self):
        """With enough hops, dev-intern-role -> ci-deploy-role -> prod buckets
        should surface as a privilege escalation path."""
        graph = InfraGraph().build_from_seed()
        result = graph.simulate_blast_radius("dev-intern-role", max_hops=5)

        assert "prod-data-lake-raw" in result.reachable_resources
        assert "customer-reports-q1" in result.reachable_resources
        assert result.severity == "CRITICAL"
        assert result.critical_resources_reached

    def test_ci_deploy_role_directly_reaches_critical_resources(self):
        graph = InfraGraph().build_from_seed()
        result = graph.simulate_blast_radius("ci-deploy-role", max_hops=1)

        assert "prod-data-lake-raw" in result.reachable_resources
        assert "backup-vault" in result.reachable_resources
        assert result.severity == "CRITICAL"

    def test_max_hops_caps_traversal(self):
        graph = InfraGraph().build_from_seed()
        shallow = graph.simulate_blast_radius("dev-intern-role", max_hops=1)
        deep = graph.simulate_blast_radius("dev-intern-role", max_hops=5)

        assert len(shallow.reachable_resources) < len(deep.reachable_resources)
        assert shallow.max_depth <= 1

    def test_path_is_recorded_for_each_reachable_node(self):
        graph = InfraGraph().build_from_seed()
        result = graph.simulate_blast_radius("dev-intern-role", max_hops=5)

        path = result.paths["prod-data-lake-raw"]
        assert path[0] == "dev-intern-role"
        assert path[-1] == "prod-data-lake-raw"
        assert "ci-deploy-role" in path

    def test_isolated_node_has_empty_blast_radius(self):
        graph = InfraGraph()
        graph.add_node("lonely-role", "IAMRole")
        result = graph.simulate_blast_radius("lonely-role")

        assert result.reachable_resources == []
        assert result.severity == "LOW"

    def test_unknown_entry_point_raises(self):
        graph = InfraGraph().build_from_seed()
        with pytest.raises(ValueError):
            graph.simulate_blast_radius("does-not-exist")

    def test_no_double_counting_in_cyclic_graph(self):
        """sg-web-public -> sg-db-internal exists; ensure BFS doesn't loop forever
        or double-count nodes reachable via multiple paths."""
        graph = InfraGraph()
        graph.add_node("a", "IAMRole")
        graph.add_node("b", "S3Bucket")
        graph.add_node("c", "S3Bucket")
        graph.add_edge("a", "b", "can_read")
        graph.add_edge("a", "c", "can_read")
        graph.add_edge("b", "c", "can_read")
        graph.add_edge("c", "b", "can_read")  # cycle

        result = graph.simulate_blast_radius("a", max_hops=5)
        assert sorted(result.reachable_resources) == ["b", "c"]


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------

class TestSeverityScoring:
    def test_two_critical_resources_is_critical(self):
        graph = InfraGraph()
        graph.add_node("role", "IAMRole")
        graph.add_node("r1", "S3Bucket", tags=["production"])
        graph.add_node("r2", "S3Bucket", tags=["pii"])
        graph.add_edge("role", "r1", "can_read")
        graph.add_edge("role", "r2", "can_read")

        result = graph.simulate_blast_radius("role")
        assert result.severity == "CRITICAL"

    def test_one_critical_resource_is_high(self):
        graph = InfraGraph()
        graph.add_node("role", "IAMRole")
        graph.add_node("r1", "S3Bucket", tags=["production"])
        graph.add_edge("role", "r1", "can_read")

        result = graph.simulate_blast_radius("role")
        assert result.severity == "HIGH"

    def test_many_noncritical_resources_is_medium(self):
        graph = InfraGraph()
        graph.add_node("role", "IAMRole")
        for i in range(4):
            graph.add_node(f"r{i}", "S3Bucket")
            graph.add_edge("role", f"r{i}", "can_read")

        result = graph.simulate_blast_radius("role")
        assert result.severity == "MEDIUM"

    def test_few_noncritical_resources_is_low(self):
        graph = InfraGraph()
        graph.add_node("role", "IAMRole")
        graph.add_node("r1", "S3Bucket")
        graph.add_edge("role", "r1", "can_read")

        result = graph.simulate_blast_radius("role")
        assert result.severity == "LOW"


# ---------------------------------------------------------------------------
# Scoped IAM policy parser
# ---------------------------------------------------------------------------

class TestIAMPolicyParsing:
    def _base_graph(self):
        graph = InfraGraph()
        graph.add_node("victim-bucket", "S3Bucket", tags=["production"])
        graph.add_node("other-bucket", "S3Bucket")
        graph.add_node("some-table", "DynamoDBTable")
        return graph

    def test_wildcard_action_grants_administer(self):
        graph = self._base_graph()
        roles = [{
            "role_name": "admin-role",
            "policies": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        }]
        graph.build_from_iam_policies(roles)

        edges = dict((t, e) for t, e in graph.adjacency["admin-role"])
        assert edges["victim-bucket"] == "can_administer"
        assert edges["other-bucket"] == "can_administer"
        assert "some-table" not in edges  # wrong service prefix

    def test_read_only_action_grants_can_read(self):
        graph = self._base_graph()
        roles = [{
            "role_name": "reader-role",
            "policies": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }]
        graph.build_from_iam_policies(roles)

        edges = dict((t, e) for t, e in graph.adjacency["reader-role"])
        assert edges["victim-bucket"] == "can_read"

    def test_write_action_grants_can_write(self):
        graph = self._base_graph()
        roles = [{
            "role_name": "writer-role",
            "policies": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}],
        }]
        graph.build_from_iam_policies(roles)

        edges = dict((t, e) for t, e in graph.adjacency["writer-role"])
        assert edges["victim-bucket"] == "can_write"

    def test_explicit_deny_overrides_allow(self):
        graph = self._base_graph()
        roles = [{
            "role_name": "blocked-role",
            "policies": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:*", "Resource": "victim-bucket"},
            ],
        }]
        graph.build_from_iam_policies(roles)

        edges = dict((t, e) for t, e in graph.adjacency["blocked-role"])
        assert "victim-bucket" not in edges
        assert edges["other-bucket"] == "can_administer"

    def test_resource_prefix_wildcard_matches(self):
        graph = InfraGraph()
        graph.add_node("prod-data-lake-raw", "S3Bucket", tags=["production"])
        graph.add_node("dev-bucket", "S3Bucket")

        roles = [{
            "role_name": "scoped-role",
            "policies": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "prod-*"}],
        }]
        graph.build_from_iam_policies(roles)

        edges = dict((t, e) for t, e in graph.adjacency["scoped-role"])
        assert edges.get("prod-data-lake-raw") == "can_read"
        assert "dev-bucket" not in edges

    def test_trust_policy_creates_assume_role_edge(self):
        graph = self._base_graph()
        graph.add_node("junior-role", "IAMRole")
        graph.add_node("senior-role", "IAMRole")

        graph.build_from_iam_policies(
            roles=[{"role_name": "senior-role", "policies": []}],
            trust_policies=[{"role_name": "senior-role", "trusted_principals": ["junior-role"]}],
        )

        edges = dict((t, e) for t, e in graph.adjacency["junior-role"])
        assert edges["senior-role"] == "can_assume"

    def test_blast_radius_via_parsed_policies(self):
        """End-to-end: parse a policy set, then run BFS across the result."""
        graph = self._base_graph()
        roles = [{
            "role_name": "escalator",
            "policies": [{"Effect": "Allow", "Action": "s3:*", "Resource": "victim-bucket"}],
        }]
        graph.build_from_iam_policies(roles)

        result = graph.simulate_blast_radius("escalator")
        assert "victim-bucket" in result.reachable_resources
        assert result.severity == "HIGH"

    def test_source_ip_restricted_allow_grants_no_edge(self):
        """GROWTH_PLAN.md Phase 7: an Allow gated on aws:SourceIp isn't
        usable by an attacker with merely stolen long-lived credentials —
        the scenario blast radius models — so it should not count as a real
        edge, unlike an unconditional grant of the same action/resource."""
        graph = self._base_graph()
        roles = [{
            "role_name": "office-only-role",
            "policies": [{
                "Effect": "Allow", "Action": "s3:*", "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            }],
        }]
        graph.build_from_iam_policies(roles)

        edges = dict((t, e) for t, e in graph.adjacency.get("office-only-role", []))
        assert edges == {}

    def test_mfa_restricted_allow_grants_no_edge(self):
        graph = self._base_graph()
        roles = [{
            "role_name": "mfa-gated-role",
            "policies": [{
                "Effect": "Allow", "Action": "s3:*", "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            }],
        }]
        graph.build_from_iam_policies(roles)

        edges = dict((t, e) for t, e in graph.adjacency.get("mfa-gated-role", []))
        assert edges == {}

    def test_unconditional_allow_alongside_restricted_one_still_grants_edge(self):
        """Only the conditioned statement is excluded — a role with both a
        restricted grant and a genuinely unconditional one should still show
        the edge the unconditional statement grants."""
        graph = self._base_graph()
        roles = [{
            "role_name": "mixed-role",
            "policies": [
                {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*",
                 "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}},
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            ],
        }]
        graph.build_from_iam_policies(roles)

        edges = dict((t, e) for t, e in graph.adjacency["mixed-role"])
        assert edges["victim-bucket"] == "can_read"

    def test_unrelated_condition_key_is_unaffected(self):
        """Only aws:SourceIp/aws:MultiFactorAuthPresent are treated as
        restrictive — any other condition key is a documented, unhandled
        gap, not silently over-claimed as solved; the grant still counts."""
        graph = self._base_graph()
        roles = [{
            "role_name": "date-limited-role",
            "policies": [{
                "Effect": "Allow", "Action": "s3:*", "Resource": "*",
                "Condition": {"DateLessThan": {"aws:CurrentTime": "2027-01-01T00:00:00Z"}},
            }],
        }]
        graph.build_from_iam_policies(roles)

        edges = dict((t, e) for t, e in graph.adjacency["date-limited-role"])
        assert edges["victim-bucket"] == "can_administer"
