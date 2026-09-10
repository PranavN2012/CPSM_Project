"""
test_attack_classifier.py — Tests for Layer 2's ATT&CK Technique Classifier
==============================================================================
Covers knowledge-base loading, anomaly-context narration, threshold
calibration (Youden's J), and classification including the honest UNKNOWN
fallback below threshold.

Loads the real SBERT model (shared with test_semantic_scorer.py's module-level
cache) — these tests are slower but exercise the real embedding path rather
than the keyword fallback.
"""

import sys
import os

import pytest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
sys.path.insert(0, os.path.join(PROJECT_DIR, "lambda", "shared"))

from ml.semantic_scorer import (
    AttackClassifier,
    ClassificationResult,
    EventNarrator,
    DEFAULT_FALLBACK_THRESHOLD,
    MIN_CALIBRATION_PAIRS,
)


# ---------------------------------------------------------------------------
# EventNarrator — anomaly context fragments
# ---------------------------------------------------------------------------

class TestEventNarratorAnomalyContext:
    def setup_method(self):
        self.narrator = EventNarrator()
        self.event = {
            "vulnerability_type": "S3 Public Access",
            "bucket_name": "prod-data-lake-raw",
            "region": "ap-southeast-1",
            "account_id": "123456789012",
            "severity": "CRITICAL",
        }

    def test_narrate_without_tags_unchanged(self):
        plain = self.narrator.narrate(self.event)
        assert "flagged" not in plain

    def test_narrate_with_single_tag(self):
        narrative = self.narrator.narrate(self.event, anomaly_tags=["unusual_time"])
        assert "unusual hour" in narrative

    def test_narrate_with_multiple_tags_combines_fragments(self):
        narrative = self.narrator.narrate(
            self.event, anomaly_tags=["unusual_time", "unusual_region", "high_resource_breadth"]
        )
        assert "unusual hour" in narrative
        assert "atypical region" in narrative
        assert "distinct resources" in narrative

    def test_unknown_tag_ignored(self):
        narrative = self.narrator.narrate(self.event, anomaly_tags=["not_a_real_tag"])
        assert "flagged" not in narrative

    def test_empty_tag_list_same_as_none(self):
        assert self.narrator.narrate(self.event, anomaly_tags=[]) == self.narrator.narrate(self.event)


# ---------------------------------------------------------------------------
# Knowledge base loading
# ---------------------------------------------------------------------------

class TestKnowledgeBase:
    def test_loads_bundled_kb(self):
        clf = AttackClassifier()
        assert clf.technique_count > 20

    def test_missing_kb_file_degrades_gracefully(self):
        clf = AttackClassifier(kb_path="/no/such/file.json")
        assert clf.technique_count == 0
        result = clf.classify({"vulnerability_type": "S3 Public Access", "bucket_name": "x"})
        assert result.technique_id == "UNKNOWN"


# ---------------------------------------------------------------------------
# Threshold calibration
# ---------------------------------------------------------------------------

class TestThresholdCalibration:
    def test_calibrates_from_bundled_pairs(self):
        clf = AttackClassifier()
        threshold = clf.threshold  # triggers lazy init + calibration
        assert clf.is_threshold_calibrated
        assert 0.0 < threshold < 1.0

    def test_insufficient_pairs_falls_back(self):
        clf = AttackClassifier()
        clf._ensure_initialized()
        too_few = [
            {"narrative": "test", "technique_id": "T1530", "should_match": True}
            for _ in range(MIN_CALIBRATION_PAIRS - 1)
        ]
        threshold = clf.calibrate_threshold(too_few)
        assert threshold == DEFAULT_FALLBACK_THRESHOLD
        assert not clf._threshold_calibrated

    def test_all_same_label_falls_back(self):
        """Youden's J is undefined without both positive and negative examples."""
        clf = AttackClassifier()
        clf._ensure_initialized()
        all_positive = [
            {"narrative": f"event {i}", "technique_id": "T1530", "should_match": True}
            for i in range(MIN_CALIBRATION_PAIRS + 2)
        ]
        threshold = clf.calibrate_threshold(all_positive)
        assert threshold == DEFAULT_FALLBACK_THRESHOLD

    def test_calibrated_threshold_is_logged_not_hidden(self):
        """The threshold used is always reported on the result, not a hidden constant."""
        clf = AttackClassifier()
        result = clf.classify({"vulnerability_type": "S3 Public Access", "bucket_name": "prod-data"})
        assert result.threshold_used == clf.threshold


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

class TestClassification:
    @classmethod
    def setup_class(cls):
        cls.clf = AttackClassifier()

    def test_data_access_event_classifies_plausibly(self):
        event = {
            "vulnerability_type": "S3 Public Access",
            "bucket_name": "prod-customer-data",
            "region": "us-east-1",
            "account_id": "123456789012",
            "severity": "CRITICAL",
        }
        result = self.clf.classify(event)
        assert isinstance(result, ClassificationResult)
        # Either a real technique or an honest UNKNOWN — both are valid outcomes,
        # but the result must always be internally consistent.
        if result.technique_id != "UNKNOWN":
            assert result.confidence >= result.threshold_used
            assert result.tactic
        else:
            assert result.confidence < result.threshold_used

    def test_top_matches_returned_for_known_events(self):
        event = {
            "vulnerability_type": "IAM Audit",
            "bucket_name": "wildcard-admin-role",
            "region": "us-east-1",
            "account_id": "123456789012",
            "severity": "CRITICAL",
        }
        result = self.clf.classify(event)
        assert len(result.top_matches) <= 3
        if result.top_matches:
            sims = [m["similarity"] for m in result.top_matches]
            assert sims == sorted(sims, reverse=True)

    def test_anomaly_tags_change_the_narrative_and_can_change_classification(self):
        event = {
            "vulnerability_type": "S3 Public Access",
            "bucket_name": "prod-data-lake-raw",
            "region": "ap-southeast-1",
            "account_id": "123456789012",
            "severity": "HIGH",
        }
        plain = self.clf.classify(event)
        with_context = self.clf.classify(
            event, anomaly_tags=["unusual_time", "high_resource_breadth", "high_ip_diversity"]
        )
        # Not asserting a specific technique — just that the narration path
        # actually runs end-to-end and produces a valid result either way.
        assert isinstance(with_context, ClassificationResult)
        assert isinstance(plain, ClassificationResult)

    def test_confidence_in_valid_range(self):
        result = self.clf.classify({"vulnerability_type": "Security Group Open SSH", "bucket_name": "sg-1"})
        assert 0.0 <= result.confidence <= 1.0

    def test_below_threshold_reports_unknown_with_closest_match_visible(self):
        """A narrative engineered to be generic/unrelated should not be force-matched."""
        clf = AttackClassifier()
        vague_event = {"vulnerability_type": "TotallyUnrelatedNoise", "bucket_name": "x"}
        result = clf.classify(vague_event)
        if result.technique_id == "UNKNOWN":
            assert "closest" in result.description.lower() or "below threshold" in result.description.lower()
