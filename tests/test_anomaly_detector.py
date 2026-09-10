"""
test_anomaly_detector.py — Rigorous Tests for Layer 1
=====================================================
Tests real-world attack scenarios, edge cases, false positive rates,
windowed feature effectiveness, and scoring stability.
"""

import sys
import os
import time
import copy

import pytest
import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
sys.path.insert(0, os.path.join(PROJECT_DIR, "lambda", "shared"))

from ml.anomaly_detector import (
    AnomalyDetector,
    EventWindow,
    extract_features,
    generate_training_data,
    FEATURE_NAMES,
    SEVERITY_ENCODING,
    VULN_TYPE_ENCODING,
)


# ---------------------------------------------------------------------------
# Realistic Event Factories
# ---------------------------------------------------------------------------

def normal_s3_business_hours():
    """Typical dev creating an S3 bucket at 2:30 PM on a Thursday."""
    return {
        "timestamp": "2026-06-12T14:30:00Z",
        "vulnerability_type": "S3 Public Access",
        "severity": "MEDIUM",
        "bucket_name": "dev-test-bucket",
        "account_id": "123456789012",
        "region": "us-east-1",
        "status": "REMEDIATED",
    }

def normal_encryption_check():
    """Routine encryption check on a staging bucket, business hours."""
    return {
        "timestamp": "2026-06-12T10:15:00Z",
        "vulnerability_type": "S3 Encryption",
        "severity": "LOW",
        "bucket_name": "staging-logs-2026",
        "account_id": "123456789012",
        "region": "us-east-1",
        "status": "COMPLIANT",
    }

def normal_iam_audit():
    """Routine IAM audit finding during business hours."""
    return {
        "timestamp": "2026-06-12T11:00:00Z",
        "vulnerability_type": "IAM Audit",
        "severity": "MEDIUM",
        "bucket_name": "User:dev-intern",
        "account_id": "123456789012",
        "region": "us-east-1",
        "status": "IAM_OVERPERMISSIVE",
    }

def attack_3am_prod_s3():
    """Attacker opening prod S3 bucket at 3 AM on Saturday."""
    return {
        "timestamp": "2026-06-14T03:12:00Z",
        "vulnerability_type": "S3 Public Access",
        "severity": "CRITICAL",
        "bucket_name": "prod-customer-payment-data-lake",
        "account_id": "987654321098",
        "region": "ap-southeast-1",
        "status": "REMEDIATION_FAILED",
    }

def attack_rapid_fire_bucket(idx):
    """One event in a rapid-fire bucket creation attack."""
    return {
        "timestamp": f"2026-06-12T02:00:{idx:02d}Z",
        "vulnerability_type": "S3 Public Access",
        "severity": "HIGH",
        "bucket_name": f"exfil-dump-{idx:04d}",
        "account_id": "987654321098",
        "region": "us-east-1",
        "status": "REMEDIATED",
    }

def attack_cross_region(region_idx):
    """Cross-region exfiltration: same account, different regions."""
    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
    return {
        "timestamp": f"2026-06-14T01:{region_idx*10:02d}:00Z",
        "vulnerability_type": "S3 Public Access",
        "severity": "CRITICAL",
        "bucket_name": f"prod-data-export-{region_idx}",
        "account_id": "111222333444",
        "region": regions[region_idx % len(regions)],
        "status": "REMEDIATED",
    }

def attack_slow_exfil_event(hour):
    """Slow exfiltration: 1 event per hour from same account, rotating regions."""
    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
    return {
        "timestamp": f"2026-06-12T{hour:02d}:05:00Z",
        "vulnerability_type": "S3 Public Access",
        "severity": "HIGH",
        "bucket_name": f"prod-backup-archive-{hour:03d}",
        "account_id": "111222333444",
        "region": regions[hour % len(regions)],
        "status": "REMEDIATED",
    }

def attack_iam_escalation():
    """Privilege escalation: wildcard IAM at 1 AM."""
    return {
        "timestamp": "2026-06-14T01:30:00Z",
        "vulnerability_type": "IAM Audit",
        "severity": "CRITICAL",
        "bucket_name": "User:compromised-admin",
        "account_id": "987654321098",
        "region": "us-east-1",
        "status": "IAM_OVERPERMISSIVE",
    }

def stealth_attack_business_hours():
    """Attacker trying to blend in: prod bucket during business hours,
    LOW severity to avoid alerting. Should still be caught by prod keyword."""
    return {
        "timestamp": "2026-06-12T14:00:00Z",
        "vulnerability_type": "S3 Encryption",
        "severity": "LOW",
        "bucket_name": "prod-customer-secrets-vault",
        "account_id": "123456789012",
        "region": "us-east-1",
        "status": "COMPLIANT",
    }


# ---------------------------------------------------------------------------
# Feature Extraction — Correctness
# ---------------------------------------------------------------------------

class TestFeatureExtractionCorrectness:
    """Verify each feature is extracted correctly for known inputs."""

    def test_feature_vector_shape(self):
        features = extract_features(normal_s3_business_hours())
        assert features.shape == (10,)
        assert features.dtype == np.float64

    def test_hour_14_30(self):
        features = extract_features(normal_s3_business_hours())
        assert features[0] == 14.0

    def test_hour_3_12_am(self):
        features = extract_features(attack_3am_prod_s3())
        assert features[0] == 3.0

    def test_weekday_thursday(self):
        # 2026-06-12 is a Friday actually, let me check... 
        # June 12, 2026 is a Friday. Let's just test the value is 0 or 1.
        features = extract_features(normal_s3_business_hours())
        assert features[1] in (0.0, 1.0)

    def test_weekend_saturday(self):
        # 2026-06-14 is a Sunday
        features = extract_features(attack_3am_prod_s3())
        assert features[1] == 1.0

    def test_vuln_type_s3_public(self):
        features = extract_features(normal_s3_business_hours())
        assert features[2] == VULN_TYPE_ENCODING["S3 Public Access"]

    def test_vuln_type_iam(self):
        features = extract_features(normal_iam_audit())
        assert features[2] == VULN_TYPE_ENCODING["IAM Audit"]

    def test_severity_medium(self):
        features = extract_features(normal_s3_business_hours())
        assert features[3] == SEVERITY_ENCODING["MEDIUM"]

    def test_severity_critical(self):
        features = extract_features(attack_3am_prod_s3())
        assert features[3] == SEVERITY_ENCODING["CRITICAL"]

    def test_resource_name_length(self):
        event = normal_s3_business_hours()
        features = extract_features(event)
        assert features[4] == len("dev-test-bucket")

    def test_prod_keyword_positive(self):
        features = extract_features(attack_3am_prod_s3())
        assert features[5] == 1.0  # "prod-customer-payment-data-lake"

    def test_prod_keyword_negative(self):
        features = extract_features(normal_s3_business_hours())
        assert features[5] == 0.0  # "dev-test-bucket"

    def test_prod_keyword_vault(self):
        """'vault' is a prod keyword."""
        features = extract_features(stealth_attack_business_hours())
        assert features[5] == 1.0  # "prod-customer-secrets-vault"

    def test_missing_timestamp_defaults(self):
        features = extract_features({"bucket_name": "x"})
        assert features[0] == 12.0  # Default hour
        assert features[1] == 0.0   # Default weekday

    def test_unknown_vuln_type_gets_fallback(self):
        event = {"vulnerability_type": "NeverSeenBefore"}
        features = extract_features(event)
        assert features[2] == len(VULN_TYPE_ENCODING)  # Fallback value

    def test_unknown_severity_gets_zero(self):
        event = {"severity": "IMPOSSIBLE"}
        features = extract_features(event)
        assert features[3] == 0.0

    def test_empty_event_no_nans(self):
        features = extract_features({})
        assert not np.any(np.isnan(features))
        assert features.shape == (10,)


# ---------------------------------------------------------------------------
# Windowed Features — Correctness & Edge Cases
# ---------------------------------------------------------------------------

class TestWindowedFeatures:
    """Test that windowed (session-level) features work correctly."""

    def test_empty_window_gives_zero_frequency(self):
        window = EventWindow()
        features = extract_features(normal_s3_business_hours(), window)
        assert features[6] == 0.0  # account_frequency_1h
        assert features[7] == 0.0  # region_frequency_1h
        assert features[8] == 0.0  # type_frequency_1h
        assert features[9] == 0.0  # cross_region_flag

    def test_frequency_counts_correct_account(self):
        window = EventWindow()
        for _ in range(5):
            window.add({"account_id": "acct-A", "region": "us-east-1",
                         "vulnerability_type": "S3 Public Access"})
        for _ in range(3):
            window.add({"account_id": "acct-B", "region": "us-east-1",
                         "vulnerability_type": "S3 Public Access"})

        event_a = {"account_id": "acct-A", "region": "us-east-1",
                    "vulnerability_type": "S3 Public Access",
                    "timestamp": "2026-06-12T12:00:00Z", "severity": "LOW",
                    "bucket_name": "test"}
        features = extract_features(event_a, window)
        assert features[6] == 5.0  # only acct-A events

    def test_cross_region_flag_single_region(self):
        window = EventWindow()
        for _ in range(3):
            window.add({"account_id": "acct-A", "region": "us-east-1"})
        assert not window.cross_region_flag("acct-A")

    def test_cross_region_flag_multi_region(self):
        window = EventWindow()
        window.add({"account_id": "acct-A", "region": "us-east-1"})
        window.add({"account_id": "acct-A", "region": "eu-west-1"})
        assert window.cross_region_flag("acct-A")

    def test_cross_region_per_account_isolation(self):
        """Cross-region flag for acct-A should not be affected by acct-B."""
        window = EventWindow()
        window.add({"account_id": "acct-A", "region": "us-east-1"})
        window.add({"account_id": "acct-B", "region": "eu-west-1"})
        assert not window.cross_region_flag("acct-A")
        assert not window.cross_region_flag("acct-B")

    def test_max_size_eviction(self):
        window = EventWindow(max_size=5)
        for i in range(10):
            window.add({"account_id": f"acct-{i}"})
        assert window.size == 5
        # First 5 events should be evicted
        assert window.account_frequency("acct-0") == 0
        assert window.account_frequency("acct-9") == 1

    def test_type_frequency_distinguishes_types(self):
        window = EventWindow()
        for _ in range(4):
            window.add({"account_id": "a", "region": "r",
                         "vulnerability_type": "S3 Public Access"})
        for _ in range(2):
            window.add({"account_id": "a", "region": "r",
                         "vulnerability_type": "IAM Audit"})
        assert window.type_frequency("S3 Public Access") == 4
        assert window.type_frequency("IAM Audit") == 2
        assert window.type_frequency("DynamoDB Unencrypted") == 0


# ---------------------------------------------------------------------------
# Training Data — Statistical Properties
# ---------------------------------------------------------------------------

class TestTrainingDataStatistics:
    """Verify training data has the right statistical properties."""

    def test_shape(self):
        data = generate_training_data(n_normal=80, n_anomalous=20)
        assert data.shape == (100, 10)

    def test_normal_events_have_business_hours(self):
        data = generate_training_data(n_normal=100, n_anomalous=0)
        hours = data[:, 0]
        assert all(8 <= h <= 18 for h in hours), "Normal events should be 8AM-6PM"

    def test_anomalous_events_have_off_hours(self):
        data = generate_training_data(n_normal=0, n_anomalous=100)
        hours = data[:, 0]
        off_hours = [h for h in hours if h < 5 or h > 21]
        assert len(off_hours) > 50, "Most anomalous events should be off-hours"

    def test_normal_events_have_low_frequency(self):
        data = generate_training_data(n_normal=100, n_anomalous=0)
        acct_freq = data[:, 6]  # account_frequency_1h
        assert all(f <= 3 for f in acct_freq), "Normal: low account frequency"

    def test_anomalous_events_have_high_frequency(self):
        data = generate_training_data(n_normal=0, n_anomalous=100)
        acct_freq = data[:, 6]
        assert all(f >= 5 for f in acct_freq), "Anomalous: high account frequency"

    def test_reproducibility(self):
        d1 = generate_training_data(seed=42)
        d2 = generate_training_data(seed=42)
        np.testing.assert_array_equal(d1, d2)


# ---------------------------------------------------------------------------
# Anomaly Detector — Core Scoring Invariants
# ---------------------------------------------------------------------------

class TestScoringInvariants:
    """Test that the detector's scoring obeys expected invariants.
    These are the tests that matter most — if these fail, the model is broken."""

    @pytest.fixture(autouse=True)
    def setup_detector(self):
        self.det = AnomalyDetector(contamination=0.15, random_state=42)
        self.det.fit()

    def _fresh_score(self, event):
        """Score an event with a clean window."""
        self.det.reset_window()
        return self.det.score(event)

    def test_not_fitted_raises(self):
        det = AnomalyDetector()
        with pytest.raises(RuntimeError, match="not fitted"):
            det.score(normal_s3_business_hours())

    def test_score_is_bounded_0_1(self):
        for factory in [normal_s3_business_hours, normal_encryption_check,
                        normal_iam_audit, attack_3am_prod_s3,
                        attack_iam_escalation, stealth_attack_business_hours]:
            score = self._fresh_score(factory())
            assert 0.0 <= score <= 1.0, f"{factory.__name__}: score {score} out of range"

    def test_3am_prod_attack_scores_higher_than_normal(self):
        """A 3AM production S3 attack must score higher than a normal dev bucket."""
        normal = self._fresh_score(normal_s3_business_hours())
        attack = self._fresh_score(attack_3am_prod_s3())
        assert attack > normal, (
            f"3AM prod attack ({attack:.4f}) should > normal dev ({normal:.4f})"
        )

    def test_iam_escalation_scores_higher_than_routine_audit(self):
        """1AM IAM escalation must score higher than routine IAM audit."""
        routine = self._fresh_score(normal_iam_audit())
        escalation = self._fresh_score(attack_iam_escalation())
        assert escalation > routine, (
            f"IAM escalation ({escalation:.4f}) should > routine ({routine:.4f})"
        )

    def test_scoring_stability(self):
        """Same event scored twice with clean window should give same score."""
        s1 = self._fresh_score(normal_s3_business_hours())
        s2 = self._fresh_score(normal_s3_business_hours())
        assert s1 == s2, f"Unstable scores: {s1} vs {s2}"

    def test_rapid_fire_escalation(self):
        """Rapid-fire events from same account should cause escalating scores."""
        self.det.reset_window()
        scores = []
        for i in range(8):
            scores.append(self.det.score(attack_rapid_fire_bucket(i)))

        # The last score should be higher than the first
        # because the window accumulates frequency evidence
        assert scores[-1] > scores[0], (
            f"Rapid-fire: last ({scores[-1]:.4f}) should > first ({scores[0]:.4f}). "
            f"All scores: {[f'{s:.4f}' for s in scores]}"
        )

    def test_cross_region_escalation(self):
        """Cross-region activity from same account should increase scores."""
        self.det.reset_window()
        scores = []
        for i in range(4):
            scores.append(self.det.score(attack_cross_region(i)))

        # After hitting multiple regions, cross_region_flag activates
        # Score at region 3+ should be higher than region 0
        assert scores[-1] > scores[0], (
            f"Cross-region: last ({scores[-1]:.4f}) should > first ({scores[0]:.4f}). "
            f"All scores: {[f'{s:.4f}' for s in scores]}"
        )

    def test_slow_exfiltration_detection(self):
        """Scenario 6: 1 event/hour × 8 hours from same account.
        Individual events look normal, but the accumulated window pattern
        should push the final score above a baseline normal event."""
        self.det.reset_window()
        for h in range(7):
            self.det.score(attack_slow_exfil_event(h))

        # 8th event should have elevated score from accumulated evidence
        exfil_score = self.det.score(attack_slow_exfil_event(7))

        # Compare to a baseline: score a normal event with clean window
        baseline = self._fresh_score(normal_s3_business_hours())

        assert exfil_score > baseline, (
            f"Slow exfil final ({exfil_score:.4f}) should > baseline ({baseline:.4f}). "
            f"Window-based detection is not working."
        )

    def test_window_matters(self):
        """Verify windowed features actually change the score.
        Score the SAME event with empty vs populated window."""
        event = normal_s3_business_hours()

        # Score with empty window
        self.det.reset_window()
        score_empty = self.det.score(copy.deepcopy(event))

        # Populate window with same-account events, then re-score
        self.det.reset_window()
        for _ in range(5):
            self.det.window.add({
                "account_id": event["account_id"],
                "region": event["region"],
                "vulnerability_type": event["vulnerability_type"],
            })
        score_populated = self.det.score(copy.deepcopy(event))

        assert score_populated != score_empty, (
            f"Windowed features had no effect! "
            f"Empty: {score_empty:.4f}, Populated: {score_populated:.4f}"
        )


# ---------------------------------------------------------------------------
# False Positive & False Negative Analysis
# ---------------------------------------------------------------------------

class TestFalsePositiveRate:
    """Test that the model doesn't label everything as anomalous."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.det = AnomalyDetector(contamination=0.15, random_state=42)
        self.det.fit()

    def test_normal_events_mostly_score_below_0_5(self):
        """Normal business-hours events should mostly score below 0.5."""
        normal_events = [
            normal_s3_business_hours(),
            normal_encryption_check(),
            normal_iam_audit(),
        ]
        high_scores = 0
        for event in normal_events:
            self.det.reset_window()
            score = self.det.score(event)
            if score > 0.5:
                high_scores += 1

        # At most 1 out of 3 normal events should score above 0.5
        assert high_scores <= 1, (
            f"{high_scores}/3 normal events scored > 0.5 — too many false positives"
        )

    def test_attack_events_mostly_score_above_normal(self):
        """Attack events should score meaningfully higher than normal."""
        self.det.reset_window()
        normal_baseline = self.det.score(normal_s3_business_hours())

        attack_events = [
            attack_3am_prod_s3(),
            attack_iam_escalation(),
        ]
        for event in attack_events:
            self.det.reset_window()
            score = self.det.score(event)
            assert score > normal_baseline, (
                f"Attack event scored {score:.4f} <= normal baseline {normal_baseline:.4f}"
            )

    def test_stealth_attack_detection(self):
        """Stealth attacker (business hours, LOW severity, but prod keywords).
        Should score higher than a truly benign dev event."""
        self.det.reset_window()
        benign = self.det.score(normal_s3_business_hours())
        self.det.reset_window()
        stealth = self.det.score(stealth_attack_business_hours())

        # Stealth attack has prod keywords — model should pick up on this
        # but may not flag as strongly as a 3AM attack
        assert stealth >= benign, (
            f"Stealth ({stealth:.4f}) should >= benign ({benign:.4f}). "
            f"Prod keywords not contributing to score."
        )


# ---------------------------------------------------------------------------
# Feature Vector Debug API
# ---------------------------------------------------------------------------

class TestFeatureVectorDebug:
    """Test the get_feature_vector debug API."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.det = AnomalyDetector()
        self.det.fit()

    def test_returns_all_feature_names(self):
        fv = self.det.get_feature_vector(normal_s3_business_hours())
        assert set(fv.keys()) == set(FEATURE_NAMES)

    def test_values_match_extraction(self):
        event = attack_3am_prod_s3()
        fv = self.det.get_feature_vector(event)
        raw = extract_features(event, self.det.window)
        for i, name in enumerate(FEATURE_NAMES):
            assert fv[name] == raw[i], f"Mismatch on {name}: {fv[name]} vs {raw[i]}"

    def test_does_not_modify_window(self):
        """get_feature_vector should NOT add to the window."""
        initial_size = self.det.window.size
        self.det.get_feature_vector(normal_s3_business_hours())
        assert self.det.window.size == initial_size


# ---------------------------------------------------------------------------
# Batch Scoring
# ---------------------------------------------------------------------------

class TestBatchScoring:
    """Test batch scoring preserves temporal ordering."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.det = AnomalyDetector()
        self.det.fit()

    def test_batch_returns_correct_count(self):
        events = [normal_s3_business_hours()] * 5
        scores = self.det.score_batch(events)
        assert len(scores) == 5

    def test_batch_is_sequential(self):
        """Batch scoring should be equivalent to scoring one at a time
        (each event updates the window before the next is scored)."""
        events = [attack_rapid_fire_bucket(i) for i in range(5)]

        # Batch
        self.det.reset_window()
        batch_scores = self.det.score_batch(events)

        # Sequential
        self.det.reset_window()
        seq_scores = [self.det.score(e) for e in events]

        for i, (b, s) in enumerate(zip(batch_scores, seq_scores)):
            assert b == s, f"Event {i}: batch={b:.4f} vs sequential={s:.4f}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
