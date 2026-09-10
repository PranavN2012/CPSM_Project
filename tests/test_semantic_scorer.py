"""
test_semantic_scorer.py — Rigorous Tests for Layer 2
====================================================
Tests semantic scoring precision, cross-provider coverage, narrator
effectiveness, score ordering across event types, and adversarial inputs.
"""

import sys
import os

import pytest
import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
sys.path.insert(0, os.path.join(PROJECT_DIR, "lambda", "shared"))

from ml.semantic_scorer import (
    EventNarrator,
    SemanticScorer,
    cosine_similarity,
    KNOWN_ATTACK_PATTERNS,
)


# ---------------------------------------------------------------------------
# Realistic Event Factories
# ---------------------------------------------------------------------------

def s3_public_prod():
    """S3 public access on production bucket — should match 'public access' patterns."""
    return {
        "vulnerability_type": "S3 Public Access",
        "bucket_name": "prod-customer-data-lake",
        "region": "us-east-1",
        "account_id": "123456789012",
        "severity": "CRITICAL",
    }

def s3_encryption_missing():
    """S3 without encryption — should match 'encryption' patterns."""
    return {
        "vulnerability_type": "S3 Encryption",
        "bucket_name": "prod-financial-records",
        "region": "us-west-2",
        "account_id": "123456789012",
        "severity": "HIGH",
    }

def iam_wildcard():
    """IAM wildcard admin — should match 'wildcard/admin access' patterns."""
    return {
        "vulnerability_type": "IAM Audit",
        "bucket_name": "User:compromised-admin",
        "region": "us-east-1",
        "account_id": "987654321098",
        "severity": "CRITICAL",
    }

def sg_open_ssh():
    """Open SSH security group — should match 'SSH/brute-force' patterns."""
    return {
        "vulnerability_type": "Security Group Open SSH",
        "bucket_name": "sg-0abc123def456",
        "region": "us-east-1",
        "account_id": "123456789012",
        "severity": "HIGH",
    }

def dynamodb_unencrypted():
    """Unencrypted DynamoDB — should match 'database encryption' patterns."""
    return {
        "vulnerability_type": "DynamoDB Unencrypted",
        "bucket_name": "user-sessions-table",
        "region": "us-east-1",
        "account_id": "123456789012",
        "severity": "MEDIUM",
    }

def azure_blob_public():
    """Azure public blob — cross-provider, should still match storage patterns."""
    return {
        "vulnerability_type": "Blob Public Access",
        "bucket_name": "devuploadstemp",
        "region": "eastus",
        "account_id": "azure-sub-001",
        "severity": "HIGH",
    }

def gcp_firewall_open():
    """GCP firewall open ports — cross-provider network attack."""
    return {
        "vulnerability_type": "Firewall Open Ports",
        "bucket_name": "all",
        "region": "us-central1",
        "account_id": "gcp-project-001",
        "severity": "HIGH",
    }

def benign_dev_bucket():
    """Truly benign: dev sandbox bucket, low severity, compliant."""
    return {
        "vulnerability_type": "S3 Encryption",
        "bucket_name": "dev-test-sandbox-tmp",
        "region": "us-east-1",
        "account_id": "123456789012",
        "severity": "LOW",
    }

def nonsense_event():
    """Event with garbage data — should not crash, should score low."""
    return {
        "vulnerability_type": "XYZ_UNKNOWN_TYPE",
        "bucket_name": "aaa123bbb456ccc789",
        "region": "xx-nowhere-99",
        "account_id": "000000000000",
        "severity": "POTATO",
    }


# ---------------------------------------------------------------------------
# EventNarrator — Template Coverage & Correctness
# ---------------------------------------------------------------------------

class TestNarratorCoverage:
    """Verify every vulnerability type has a meaningful narrative."""

    ALL_VULN_TYPES = [
        "S3 Public Access", "S3 Encryption", "IAM Audit",
        "Security Group Open SSH", "DynamoDB Unencrypted",
        "Blob Public Access", "Storage Encryption", "NSG Open Ports",
        "RBAC Overpermissive", "GCS Public Access",
        "GCS Encryption (CMEK)", "Firewall Open Ports", "IAM Overpermissive",
    ]

    def test_all_types_have_dedicated_templates(self):
        """Every known vuln type should have its own template, NOT the default."""
        narrator = EventNarrator()
        for vtype in self.ALL_VULN_TYPES:
            event = {"vulnerability_type": vtype, "bucket_name": "res",
                     "region": "r", "account_id": "a", "severity": "HIGH"}
            text = narrator.narrate(event)
            assert "Security event detected" not in text, (
                f"'{vtype}' fell through to default template: {text}"
            )

    def test_narrative_includes_resource_name(self):
        narrator = EventNarrator()
        event = s3_public_prod()
        text = narrator.narrate(event)
        assert "prod-customer-data-lake" in text

    def test_narrative_includes_region(self):
        narrator = EventNarrator()
        event = s3_public_prod()
        text = narrator.narrate(event)
        assert "us-east-1" in text

    def test_narrative_includes_account(self):
        narrator = EventNarrator()
        event = s3_public_prod()
        text = narrator.narrate(event)
        assert "123456789012" in text

    def test_s3_narrative_mentions_public_access(self):
        narrator = EventNarrator()
        text = narrator.narrate(s3_public_prod())
        assert "public" in text.lower() and "access" in text.lower()

    def test_iam_narrative_mentions_overpermissive(self):
        narrator = EventNarrator()
        text = narrator.narrate(iam_wildcard())
        lower = text.lower()
        assert "overpermissive" in lower or "wildcard" in lower or "unrestricted" in lower

    def test_ssh_narrative_mentions_ssh_or_port22(self):
        narrator = EventNarrator()
        text = narrator.narrate(sg_open_ssh())
        lower = text.lower()
        assert "ssh" in lower or "22" in lower

    def test_azure_narrative_mentions_blob(self):
        narrator = EventNarrator()
        text = narrator.narrate(azure_blob_public())
        assert "blob" in text.lower() or "storage" in text.lower()

    def test_gcp_narrative_mentions_firewall(self):
        narrator = EventNarrator()
        text = narrator.narrate(gcp_firewall_open())
        assert "firewall" in text.lower()

    def test_unknown_type_uses_default_gracefully(self):
        narrator = EventNarrator()
        text = narrator.narrate(nonsense_event())
        assert isinstance(text, str)
        assert len(text) > 10

    def test_empty_event_doesnt_crash(self):
        narrator = EventNarrator()
        text = narrator.narrate({})
        assert isinstance(text, str)


# ---------------------------------------------------------------------------
# Cosine Similarity — Mathematical Correctness
# ---------------------------------------------------------------------------

class TestCosineSimilarityMath:
    def test_identical_vectors(self):
        v = np.array([1.0, 2.0, 3.0])
        assert abs(cosine_similarity(v, v) - 1.0) < 1e-6

    def test_orthogonal_vectors(self):
        v1 = np.array([1.0, 0.0])
        v2 = np.array([0.0, 1.0])
        assert abs(cosine_similarity(v1, v2)) < 1e-6

    def test_opposite_vectors(self):
        v1 = np.array([1.0, 0.0])
        v2 = np.array([-1.0, 0.0])
        assert abs(cosine_similarity(v1, v2) - (-1.0)) < 1e-6

    def test_zero_vector(self):
        assert cosine_similarity(np.zeros(3), np.array([1.0, 2.0, 3.0])) == 0.0

    def test_high_dimensional(self):
        """384-dim vectors (SBERT dimension) should work."""
        v1 = np.random.randn(384)
        v2 = np.random.randn(384)
        result = cosine_similarity(v1, v2)
        assert -1.0 <= result <= 1.0


# ---------------------------------------------------------------------------
# Known Attack Patterns — Quality
# ---------------------------------------------------------------------------

class TestAttackPatternLibrary:
    def test_minimum_count(self):
        assert len(KNOWN_ATTACK_PATTERNS) >= 10

    def test_all_non_empty(self):
        for p in KNOWN_ATTACK_PATTERNS:
            assert isinstance(p, str)
            assert len(p) > 30, f"Pattern too short to be meaningful: '{p}'"

    def test_covers_s3_attacks(self):
        combined = " ".join(KNOWN_ATTACK_PATTERNS).lower()
        assert "s3" in combined or "storage" in combined or "bucket" in combined

    def test_covers_iam_attacks(self):
        combined = " ".join(KNOWN_ATTACK_PATTERNS).lower()
        assert "iam" in combined or "privilege" in combined or "admin" in combined

    def test_covers_network_attacks(self):
        combined = " ".join(KNOWN_ATTACK_PATTERNS).lower()
        assert "ssh" in combined or "firewall" in combined or "security group" in combined

    def test_covers_exfiltration(self):
        combined = " ".join(KNOWN_ATTACK_PATTERNS).lower()
        assert "exfiltration" in combined or "multiple regions" in combined


# ---------------------------------------------------------------------------
# Semantic Scorer — Core Scoring Invariants
# ---------------------------------------------------------------------------

class TestScoringInvariants:
    """These are the tests that actually validate the ML layer works."""

    @pytest.fixture(scope="class")
    def scorer(self):
        return SemanticScorer()

    def test_all_scores_in_range(self, scorer):
        """Every event type must produce a score in [0, 1]."""
        events = [
            s3_public_prod(), s3_encryption_missing(), iam_wildcard(),
            sg_open_ssh(), dynamodb_unencrypted(), azure_blob_public(),
            gcp_firewall_open(), benign_dev_bucket(), nonsense_event(),
        ]
        for event in events:
            score = scorer.score(event)
            assert 0.0 <= score <= 1.0, (
                f"{event['vulnerability_type']}: score {score} out of range"
            )

    def test_prod_s3_attack_scores_higher_than_benign(self, scorer):
        """Production S3 public access must outscore a benign dev bucket."""
        attack = scorer.score(s3_public_prod())
        benign = scorer.score(benign_dev_bucket())
        assert attack > benign, (
            f"S3 attack ({attack:.4f}) should > benign ({benign:.4f})"
        )

    def test_iam_wildcard_scores_higher_than_benign(self, scorer):
        """IAM wildcard should score much higher than benign."""
        attack = scorer.score(iam_wildcard())
        benign = scorer.score(benign_dev_bucket())
        assert attack > benign, (
            f"IAM wildcard ({attack:.4f}) should > benign ({benign:.4f})"
        )

    def test_ssh_open_scores_higher_than_benign(self, scorer):
        """Open SSH should score higher than benign."""
        attack = scorer.score(sg_open_ssh())
        benign = scorer.score(benign_dev_bucket())
        assert attack > benign, (
            f"Open SSH ({attack:.4f}) should > benign ({benign:.4f})"
        )

    def test_nonsense_scores_lower_than_real_attacks(self, scorer):
        """Garbage events should score lower than real attack events."""
        nonsense = scorer.score(nonsense_event())
        s3_attack = scorer.score(s3_public_prod())
        assert s3_attack > nonsense, (
            f"S3 attack ({s3_attack:.4f}) should > nonsense ({nonsense:.4f})"
        )

    def test_scoring_stability(self, scorer):
        """Same event scored twice should give exactly the same score."""
        s1 = scorer.score(s3_public_prod())
        s2 = scorer.score(s3_public_prod())
        assert s1 == s2, f"Unstable: {s1} vs {s2}"

    def test_cross_provider_azure_scores_nonzero(self, scorer):
        """Azure events should still get meaningful scores even though
        attack patterns are mostly AWS-focused."""
        score = scorer.score(azure_blob_public())
        assert score > 0.1, (
            f"Azure blob score ({score:.4f}) too low — cross-provider matching failing"
        )

    def test_cross_provider_gcp_scores_nonzero(self, scorer):
        """GCP firewall events should match network attack patterns."""
        score = scorer.score(gcp_firewall_open())
        assert score > 0.1, (
            f"GCP firewall score ({score:.4f}) too low — cross-provider matching failing"
        )


# ---------------------------------------------------------------------------
# Score Ordering — Relative Ranking
# ---------------------------------------------------------------------------

class TestScoreOrdering:
    """Test that events are ranked in a sensible order."""

    @pytest.fixture(scope="class")
    def scorer(self):
        return SemanticScorer()

    def test_prod_s3_outscores_dev_s3(self, scorer):
        """Prod S3 public access should outscore dev S3 encryption."""
        prod = scorer.score(s3_public_prod())
        dev = scorer.score(benign_dev_bucket())
        assert prod > dev

    def test_all_attack_events_outscore_benign(self, scorer):
        """Every attack-type event should outscore the benign dev event."""
        benign = scorer.score(benign_dev_bucket())
        attacks = [
            ("S3 Public", s3_public_prod()),
            ("IAM Wildcard", iam_wildcard()),
            ("Open SSH", sg_open_ssh()),
        ]
        for name, event in attacks:
            score = scorer.score(event)
            assert score > benign, (
                f"{name} ({score:.4f}) should > benign ({benign:.4f})"
            )


# ---------------------------------------------------------------------------
# score_with_details — Debug API
# ---------------------------------------------------------------------------

class TestScoreWithDetails:
    """Test the detailed scoring API for explainability."""

    @pytest.fixture(scope="class")
    def scorer(self):
        return SemanticScorer()

    def test_returns_expected_keys(self, scorer):
        result = scorer.score_with_details(s3_public_prod())
        assert "score" in result
        assert "narrative" in result
        assert "top_matches" in result
        assert "using_fallback" in result

    def test_score_matches_simple_api(self, scorer):
        """score_with_details score should match score()."""
        simple = scorer.score(s3_public_prod())
        detailed = scorer.score_with_details(s3_public_prod())
        assert simple == detailed["score"]

    def test_top_matches_are_sorted(self, scorer):
        """Top matches should be in descending similarity order."""
        result = scorer.score_with_details(s3_public_prod())
        if not result["using_fallback"] and len(result["top_matches"]) >= 2:
            sims = [m["similarity"] for m in result["top_matches"]]
            assert sims == sorted(sims, reverse=True), "Top matches not sorted"

    def test_narrative_is_non_empty(self, scorer):
        result = scorer.score_with_details(s3_public_prod())
        assert len(result["narrative"]) > 20

    def test_top_match_is_relevant(self, scorer):
        """Top match for S3 public event should mention storage/S3/public."""
        result = scorer.score_with_details(s3_public_prod())
        if not result["using_fallback"] and result["top_matches"]:
            top = result["top_matches"][0]["pattern"].lower()
            relevant_keywords = ["s3", "storage", "public", "bucket", "data"]
            assert any(kw in top for kw in relevant_keywords), (
                f"Top match doesn't seem relevant to S3 public access: '{top}'"
            )


# ---------------------------------------------------------------------------
# Narrator Effectiveness — Does it actually help?
# ---------------------------------------------------------------------------

class TestNarratorEffectiveness:
    """Test that the narrator bridge actually improves scoring
    compared to just embedding raw field values."""

    @pytest.fixture(scope="class")
    def scorer(self):
        return SemanticScorer()

    def test_narrated_events_produce_differentiated_scores(self, scorer):
        """Different event types should produce meaningfully different scores.
        If all scores are nearly identical, the narrator isn't helping."""
        events = [
            s3_public_prod(),
            iam_wildcard(),
            sg_open_ssh(),
            benign_dev_bucket(),
        ]
        scores = [scorer.score(e) for e in events]
        unique_rounded = set(round(s, 2) for s in scores)

        assert len(unique_rounded) >= 2, (
            f"All scores too similar: {scores}. "
            f"Narrator may not be converting events meaningfully."
        )

    def test_narrative_contains_vulnerability_context(self):
        """Narratives should contain vulnerability-specific context,
        not just raw field values."""
        narrator = EventNarrator()

        s3_text = narrator.narrate(s3_public_prod())
        assert "public" in s3_text.lower()
        assert "access" in s3_text.lower() or "internet" in s3_text.lower()

        iam_text = narrator.narrate(iam_wildcard())
        assert "overpermissive" in iam_text.lower() or "wildcard" in iam_text.lower()

        ssh_text = narrator.narrate(sg_open_ssh())
        assert "ssh" in ssh_text.lower() or "22" in ssh_text.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
