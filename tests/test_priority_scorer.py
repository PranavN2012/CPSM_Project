"""
test_priority_scorer.py — Tests for Layer 5: Composite Priority Scoring
==========================================================================
Covers the weighted formula, severity mapping, tiering, threat-recency
computation, and explanation output.
"""

import sys
import os
from datetime import datetime, timezone, timedelta

import pytest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
sys.path.insert(0, os.path.join(PROJECT_DIR, "lambda", "shared"))

from ml.priority_scorer import (
    PriorityScorer,
    PriorityScore,
    compute_recency_score,
    WEIGHTS,
    SEVERITY_TO_SCORE,
)


# ---------------------------------------------------------------------------
# Weighted formula
# ---------------------------------------------------------------------------

class TestWeightedScoring:
    def setup_method(self):
        self.scorer = PriorityScorer()

    def test_weights_sum_to_one(self):
        assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

    def test_all_max_inputs_yields_max_score(self):
        """Recency caps at 0.9 (high, repeated probing) rather than 1.0 — a
        single signal being maximal shouldn't imply certainty the way the other
        three components can, so the ceiling here is 98, not 100."""
        result = self.scorer.score(
            anomaly_score=1.0,
            classification_confidence=1.0,
            blast_radius_severity="CRITICAL",
            pattern_key="T1530",
            history=[{"pattern_key": "T1530", "timestamp": _iso_now()}] * 3,
        )
        assert result.score == 98.0
        assert result.tier == "P1"

    def test_all_zero_inputs_yields_min_score(self):
        result = self.scorer.score(
            anomaly_score=0.0,
            classification_confidence=0.0,
            blast_radius_severity="LOW",
            pattern_key="never-seen",
        )
        # LOW severity is not zero-valued and recency defaults to "novel" (0.5),
        # so the floor isn't literally 0 — just low.
        assert result.score < 40
        assert result.tier == "P4"

    def test_blast_radius_dominates_when_other_signals_weak(self):
        """Blast radius has the largest weight (35%) — a CRITICAL blast radius
        with weak anomaly/classification should still push the score up meaningfully."""
        weak_signals = PriorityScorer().score(
            anomaly_score=0.1, classification_confidence=0.1,
            blast_radius_severity="LOW",
        )
        strong_blast = PriorityScorer().score(
            anomaly_score=0.1, classification_confidence=0.1,
            blast_radius_severity="CRITICAL",
        )
        assert strong_blast.score > weak_signals.score
        assert strong_blast.components["blast_radius"]["weighted"] > strong_blast.components["anomaly"]["weighted"]

    def test_components_breakdown_present(self):
        result = self.scorer.score(0.5, 0.5, "MEDIUM")
        for key in ("anomaly", "classification", "blast_radius", "recency"):
            assert key in result.components
            assert "weighted" in result.components[key]

    def test_explanation_mentions_tier_and_score(self):
        result = self.scorer.score(0.8, 0.7, "HIGH")
        assert result.tier in result.explanation
        assert str(result.score) in result.explanation

    def test_out_of_range_inputs_are_clamped(self):
        result = self.scorer.score(anomaly_score=5.0, classification_confidence=-3.0, blast_radius_severity="HIGH")
        assert 0 <= result.score <= 100

    def test_unknown_severity_treated_as_zero(self):
        result = self.scorer.score(0.5, 0.5, "NOT_A_SEVERITY")
        assert result.components["blast_radius"]["raw_numeric"] == 0.0


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

class TestSeverityMapping:
    @pytest.mark.parametrize("severity,expected", [
        ("LOW", 0.25), ("MEDIUM", 0.5), ("HIGH", 0.75), ("CRITICAL", 1.0),
    ])
    def test_severity_values(self, severity, expected):
        assert SEVERITY_TO_SCORE[severity] == expected

    def test_severity_case_insensitive(self):
        result = PriorityScorer().score(0.5, 0.5, "critical")
        assert result.components["blast_radius"]["raw_numeric"] == 1.0


# ---------------------------------------------------------------------------
# Tiering
# ---------------------------------------------------------------------------

class TestTiering:
    @pytest.mark.parametrize("score,expected_tier", [
        (95, "P1"), (80, "P1"), (79.9, "P2"), (60, "P2"),
        (59.9, "P3"), (40, "P3"), (39.9, "P4"), (0, "P4"),
    ])
    def test_tier_thresholds(self, score, expected_tier):
        assert PriorityScorer._tier_for(score) == expected_tier


# ---------------------------------------------------------------------------
# Threat recency
# ---------------------------------------------------------------------------

class TestThreatRecency:
    def test_never_seen_is_novel_moderate_score(self):
        score = compute_recency_score(history=[], pattern_key="T9999")
        assert score == 0.5

    def test_three_or_more_recent_occurrences_is_high(self):
        history = [{"pattern_key": "T1530", "timestamp": _iso_now()} for _ in range(3)]
        score = compute_recency_score(history, "T1530")
        assert score == 0.9

    def test_one_recent_occurrence_is_moderate(self):
        history = [{"pattern_key": "T1530", "timestamp": _iso_now()}]
        score = compute_recency_score(history, "T1530")
        assert 0.5 < score < 0.9

    def test_seen_once_long_ago_is_low(self):
        old_ts = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        history = [{"pattern_key": "T1530", "timestamp": old_ts}]
        score = compute_recency_score(history, "T1530")
        assert score == 0.2

    def test_unrelated_history_entries_ignored(self):
        history = [{"pattern_key": "T1000", "timestamp": _iso_now()} for _ in range(5)]
        score = compute_recency_score(history, "T1530")
        assert score == 0.5  # T1530 never appears -> novel

    def test_window_boundary_respected(self):
        just_outside = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        history = [{"pattern_key": "T1530", "timestamp": just_outside}]
        score = compute_recency_score(history, "T1530", window_days=7)
        assert score == 0.2  # seen before, but outside the 7-day window

    def test_malformed_timestamp_does_not_crash(self):
        history = [{"pattern_key": "T1530", "timestamp": "not-a-date"}]
        score = compute_recency_score(history, "T1530")
        assert score == 0.2  # counted as "ever seen" but not recent

    def test_future_timestamp_not_treated_as_recent(self):
        """Regression: a timestamp after `now` isn't a real past occurrence —
        a clock-skew artifact or bad data. It used to only be bounded below
        (>= cutoff), so a future timestamp was silently counted as maximally
        recent. Now bounded on both ends."""
        future_ts = "2099-01-01T00:00:00Z"
        history = [{"pattern_key": "T1530", "timestamp": future_ts}]
        score = compute_recency_score(history, "T1530")
        assert score == 0.2  # "ever seen" but not counted as recent


class TestScoreInputValidation:
    """Regression coverage for out-of-range / non-numeric score() inputs
    (negative, NaN, Infinity, None) — these used to either silently distort
    the composite score or crash outright (None raised TypeError)."""

    def setup_method(self):
        self.scorer = PriorityScorer()

    def test_out_of_range_inputs_do_not_crash(self):
        result = self.scorer.score(
            anomaly_score=-1, classification_confidence=2,
            blast_radius_severity="CRITICAL", pattern_key="x",
        )
        assert 0 <= result.score <= 100
        assert result.tier in ("P1", "P2", "P3", "P4")

    def test_nan_anomaly_does_not_crash_or_inflate_score(self):
        result = self.scorer.score(
            anomaly_score=float("nan"), classification_confidence=0.5,
            blast_radius_severity="HIGH", pattern_key="x",
        )
        assert 0 <= result.score <= 100
        assert result.components["anomaly"]["raw"] == 0.0  # NaN treated as 0, not silently maximal

    def test_infinity_anomaly_does_not_crash(self):
        result = self.scorer.score(
            anomaly_score=float("inf"), classification_confidence=0.5,
            blast_radius_severity="HIGH", pattern_key="x",
        )
        assert 0 <= result.score <= 100

    def test_none_confidence_does_not_crash(self):
        """This used to raise TypeError: '<' not supported between
        instances of 'NoneType' and 'float'."""
        result = self.scorer.score(
            anomaly_score=0.5, classification_confidence=None,
            blast_radius_severity="HIGH", pattern_key="x",
        )
        assert 0 <= result.score <= 100
        assert result.components["classification"]["raw"] == 0.0

    def test_none_severity_does_not_crash(self):
        result = self.scorer.score(
            anomaly_score=0.5, classification_confidence=0.5,
            blast_radius_severity=None, pattern_key="x",
        )
        assert 0 <= result.score <= 100


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()
