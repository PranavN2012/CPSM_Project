"""
anomaly_detector.py — Layer 1: Isolation Forest with Windowed Features
======================================================================
Detects anomalous cloud security events using sklearn's IsolationForest.

Key design decision: windowed features (account_frequency_1h, region_frequency_1h,
type_frequency_1h, cross_region_flag) are computed from a sliding window of recent
events. This solves the slow-exfiltration problem (scenario 6) where individual
events look normal but the session-level pattern is anomalous.

The model scores individual events AFTER injecting session-level context as features,
rather than scoring events in isolation and aggregating post-hoc.
"""

import time
import hashlib
from collections import deque
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ENCODING = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

VULN_TYPE_ENCODING = {
    "S3 Public Access": 0,
    "S3 Encryption": 1,
    "IAM Audit": 2,
    "Security Group Open SSH": 3,
    "DynamoDB Unencrypted": 4,
    "Blob Public Access": 5,
    "Storage Encryption": 6,
    "NSG Open Ports": 7,
    "RBAC Overpermissive": 8,
    "GCS Public Access": 9,
    "GCS Encryption (CMEK)": 10,
    "Firewall Open Ports": 11,
    "IAM Overpermissive": 12,
}

PROD_KEYWORDS = frozenset([
    "prod", "production", "customer", "pii", "payment",
    "admin", "root", "master", "credential", "secret",
    "password", "key", "vault", "backup",
])

FEATURE_NAMES = [
    "hour_of_day",
    "is_weekend",
    "event_type_encoded",
    "severity_encoded",
    "resource_name_length",
    "has_prod_keyword",
    "account_frequency_1h",
    "region_frequency_1h",
    "type_frequency_1h",
    "cross_region_flag",
]


# ---------------------------------------------------------------------------
# Sliding Window for Session-Level Features
# ---------------------------------------------------------------------------

class EventWindow:
    """Maintains a time-bounded sliding window of recent events.

    Used to compute session-level features (frequency, cross-region flags)
    that capture patterns invisible at the individual-event level.
    """

    def __init__(self, max_size=200, window_seconds=3600):
        """
        Args:
            max_size: Maximum events retained (hard cap).
            window_seconds: Time window in seconds (default 1 hour).
        """
        self._events = deque(maxlen=max_size)
        self._window_seconds = window_seconds

    def add(self, event: dict) -> None:
        """Add an event to the window with a receipt timestamp."""
        entry = {
            "event": event,
            "received_at": time.time(),
        }
        self._events.append(entry)

    def _active_events(self) -> list:
        """Return events within the time window."""
        cutoff = time.time() - self._window_seconds
        return [e for e in self._events if e["received_at"] >= cutoff]

    def account_frequency(self, account_id: str) -> int:
        """Count events from the same account in the current window."""
        return sum(
            1 for e in self._active_events()
            if e["event"].get("account_id") == account_id
        )

    def region_frequency(self, region: str) -> int:
        """Count events from the same region in the current window."""
        return sum(
            1 for e in self._active_events()
            if e["event"].get("region") == region
        )

    def type_frequency(self, vuln_type: str) -> int:
        """Count events of the same vulnerability type in the current window."""
        return sum(
            1 for e in self._active_events()
            if e["event"].get("vulnerability_type") == vuln_type
        )

    def cross_region_flag(self, account_id: str) -> bool:
        """Check if the same account has events in multiple regions."""
        regions = set()
        for e in self._active_events():
            if e["event"].get("account_id") == account_id:
                regions.add(e["event"].get("region", ""))
        return len(regions) > 1

    @property
    def size(self) -> int:
        return len(self._events)

    def clear(self) -> None:
        self._events.clear()


# ---------------------------------------------------------------------------
# Feature Extraction
# ---------------------------------------------------------------------------

def _parse_hour(event: dict) -> int:
    """Extract hour of day (0-23) from event timestamp."""
    ts = event.get("timestamp", "")
    if not ts:
        return 12  # Default to noon (neutral)
    try:
        # Handle ISO 8601 timestamps
        if "T" in ts:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        else:
            dt = datetime.now(timezone.utc)
        return dt.hour
    except (ValueError, TypeError):
        return 12


def _is_weekend(event: dict) -> int:
    """Check if the event occurred on a weekend (Sat=5, Sun=6)."""
    ts = event.get("timestamp", "")
    if not ts:
        return 0
    try:
        if "T" in ts:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        else:
            return 0
        return 1 if dt.weekday() >= 5 else 0
    except (ValueError, TypeError):
        return 0


def _has_prod_keyword(resource_name: str) -> int:
    """Check if resource name contains production-related keywords."""
    name_lower = resource_name.lower()
    return 1 if any(kw in name_lower for kw in PROD_KEYWORDS) else 0


def extract_features(event: dict, window: EventWindow = None) -> np.ndarray:
    """Extract a 10-dimensional feature vector from a security event.

    Features 0-5 are per-event (static).
    Features 6-9 are windowed (session-level), computed from the EventWindow.

    Args:
        event: Security event dict with keys like 'timestamp', 'vulnerability_type',
               'severity', 'bucket_name', 'account_id', 'region'.
        window: Optional EventWindow for computing session-level features.

    Returns:
        numpy array of shape (10,) with float64 values.
    """
    resource_name = event.get("bucket_name", event.get("resource_id", ""))
    account_id = event.get("account_id", "")
    region = event.get("region", "")
    vuln_type = event.get("vulnerability_type", "")

    # Per-event features
    hour = _parse_hour(event)
    weekend = _is_weekend(event)
    type_enc = VULN_TYPE_ENCODING.get(vuln_type, len(VULN_TYPE_ENCODING))
    sev_enc = SEVERITY_ENCODING.get(event.get("severity", ""), 0)
    name_len = len(resource_name)
    prod_flag = _has_prod_keyword(resource_name)

    # Windowed features (session-level)
    if window is not None:
        acct_freq = window.account_frequency(account_id)
        reg_freq = window.region_frequency(region)
        type_freq = window.type_frequency(vuln_type)
        cross_reg = 1 if window.cross_region_flag(account_id) else 0
    else:
        acct_freq = 0
        reg_freq = 0
        type_freq = 0
        cross_reg = 0

    return np.array([
        hour,           # 0: hour_of_day
        weekend,        # 1: is_weekend
        type_enc,       # 2: event_type_encoded
        sev_enc,        # 3: severity_encoded
        name_len,       # 4: resource_name_length
        prod_flag,      # 5: has_prod_keyword
        acct_freq,      # 6: account_frequency_1h
        reg_freq,       # 7: region_frequency_1h
        type_freq,      # 8: type_frequency_1h
        cross_reg,      # 9: cross_region_flag
    ], dtype=np.float64)


# ---------------------------------------------------------------------------
# Training Data Generator
# ---------------------------------------------------------------------------

def generate_training_data(n_normal=80, n_anomalous=20, seed=42) -> np.ndarray:
    """Generate synthetic training data for the Isolation Forest.

    Creates a mix of normal cloud operations and anomalous patterns.
    The contamination ratio matches the IsolationForest setting (~20%).

    Returns:
        numpy array of shape (n_normal + n_anomalous, 10).
    """
    rng = np.random.RandomState(seed)
    data = []

    # Normal events: business hours, low frequency, single region
    for _ in range(n_normal):
        data.append([
            rng.choice(range(8, 19)),      # hour: 8AM-6PM
            0,                              # weekday
            rng.randint(0, 5),              # common vuln types
            rng.choice([1, 2]),             # LOW or MEDIUM severity
            rng.randint(10, 30),            # typical name length
            1 if rng.random() < 0.05 else 0,  # rarely prod (5%) — kept low so
                                               # the prod-keyword signal stays
                                               # discriminative for IsolationForest;
                                               # at 25% noise it washes out entirely
            rng.randint(0, 3),              # low account frequency
            rng.randint(0, 2),              # low region frequency
            rng.randint(0, 2),              # low type frequency
            0,                              # no cross-region
        ])

    # Anomalous events: off-hours, high frequency, cross-region, prod resources
    for _ in range(n_anomalous):
        data.append([
            rng.choice([0, 1, 2, 3, 4, 22, 23]),  # off-hours
            rng.choice([0, 1]),                     # could be weekend
            rng.randint(0, 13),                     # any vuln type
            rng.choice([3, 4]),                     # HIGH or CRITICAL
            rng.randint(20, 60),                    # longer names (auto-generated)
            1,                                       # prod keyword
            rng.randint(5, 15),                     # high account frequency
            rng.randint(3, 8),                      # high region frequency
            rng.randint(3, 10),                     # high type frequency
            1,                                       # cross-region
        ])

    return np.array(data, dtype=np.float64)


# ---------------------------------------------------------------------------
# Anomaly Detector (Layer 1)
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Layer 1: Isolation Forest anomaly detector with windowed features.

    The model is trained on synthetic data representing normal vs. anomalous
    cloud security event patterns. Scores are normalized to [0, 1] where
    higher values indicate more anomalous events.

    The EventWindow maintains a sliding window of recent events, enabling
    session-level features that detect slow exfiltration patterns.
    """

    def __init__(self, contamination=0.15, n_estimators=100, random_state=42):
        """
        Args:
            contamination: Expected fraction of anomalous events in training data.
            n_estimators: Number of trees in the Isolation Forest.
            random_state: Seed for reproducibility.
        """
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )
        self.window = EventWindow(max_size=200, window_seconds=3600)
        self._is_fitted = False
        self._random_state = random_state

    def fit(self, training_data: np.ndarray = None) -> "AnomalyDetector":
        """Train the Isolation Forest on synthetic or provided data.

        Args:
            training_data: Optional pre-built feature matrix. If None, generates
                           synthetic training data automatically.

        Returns:
            self (for chaining).
        """
        if training_data is None:
            training_data = generate_training_data(seed=self._random_state)
        self.model.fit(training_data)
        self._is_fitted = True
        return self

    def score(self, event: dict) -> float:
        """Score a single event for anomalousness.

        1. Extracts 10 features (6 per-event + 4 windowed).
        2. Feeds through IsolationForest.
        3. Normalizes the raw score to [0, 1].
        4. Adds the event to the sliding window.

        Args:
            event: Security event dict.

        Returns:
            Float in [0, 1]. Higher = more anomalous.

        Raises:
            RuntimeError: If model has not been fitted yet.
        """
        if not self._is_fitted:
            raise RuntimeError(
                "AnomalyDetector not fitted. Call fit() before score()."
            )

        features = extract_features(event, self.window)
        feature_matrix = features.reshape(1, -1)

        # IsolationForest.decision_function returns negative for anomalies
        # and positive for normal. We invert and normalize to [0, 1].
        raw_score = self.model.decision_function(feature_matrix)[0]

        # Normalize: raw_score typically ranges from about -0.5 to 0.5
        # We map it so that -0.5 → 1.0 (very anomalous) and 0.5 → 0.0 (normal)
        normalized = max(0.0, min(1.0, 0.5 - raw_score))

        # Add to window AFTER scoring (so this event doesn't inflate its own frequency)
        self.window.add(event)

        return round(normalized, 4)

    def score_batch(self, events: list) -> list:
        """Score multiple events in sequence.

        Events are processed in order — each one updates the window before
        the next is scored, preserving temporal dependencies.

        Args:
            events: List of security event dicts.

        Returns:
            List of anomaly scores (floats in [0, 1]).
        """
        return [self.score(e) for e in events]

    def get_feature_vector(self, event: dict) -> dict:
        """Extract and return the named feature vector for debugging.

        Does NOT add the event to the window or modify state.

        Args:
            event: Security event dict.

        Returns:
            Dict mapping feature names to values.
        """
        features = extract_features(event, self.window)
        return dict(zip(FEATURE_NAMES, features.tolist()))

    def reset_window(self) -> None:
        """Clear the event window. Useful between test runs."""
        self.window.clear()

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted
