"""
priority_scorer.py — Layer 5: Composite Priority Scoring
==========================================================
Combines the outputs of Layers 1-3 into a single 0-100 priority score and
P1-P4 tier, so a human reviewer sees one number instead of three.

Threat recency replaces the CISA KEV component from earlier drafts of this
design: KEV lists specific CVEs (software vulnerabilities), while ATT&CK
techniques are abstract behaviors — there's no clean mapping between the two
abstraction levels, and no mechanism to actually compute a KEV match here.
Recency is computed instead from the system's own detection history (has
this technique/pattern been seen recently in this environment?), which
operates at the same abstraction level as the other three components and
needs no external feed.

Weights:
    Anomaly confidence (Layer 1)               25%
    ATT&CK classification confidence (Layer 2)  20%
    Blast radius severity (Layer 3)             35%
    Threat recency (own detection history)      20%
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

WEIGHTS = {
    "anomaly": 0.25,
    "classification": 0.20,
    "blast_radius": 0.35,
    "recency": 0.20,
}

SEVERITY_TO_SCORE = {
    "LOW": 0.25,
    "MEDIUM": 0.5,
    "HIGH": 0.75,
    "CRITICAL": 1.0,
}

TIER_THRESHOLDS = [
    (80, "P1"),
    (60, "P2"),
    (40, "P3"),
    (0, "P4"),
]

RECENCY_WINDOW_DAYS = 7
RECENCY_REPEAT_THRESHOLD = 3   # 3+ occurrences in window -> high recency score
RECENCY_HIGH_SCORE = 0.9
RECENCY_NOVEL_SCORE = 0.5      # never seen before -> moderate, worth attention
RECENCY_ISOLATED_SCORE = 0.2   # seen before, but not recently -> low


@dataclass
class PriorityScore:
    score: float
    tier: str
    explanation: str
    components: dict = field(default_factory=dict)


def compute_recency_score(history: list, pattern_key: str, now: datetime = None,
                           window_days: int = RECENCY_WINDOW_DAYS) -> float:
    """Score how "recently active" a pattern_key (e.g. an ATT&CK technique ID
    or vulnerability_type) is, based on the system's own detection history.

    Args:
        history: list of {"pattern_key": str, "timestamp": ISO8601 str} dicts,
                 e.g. sourced from a DynamoDB scan of past incidents.
        pattern_key: the technique/pattern to check recency for.
        now: reference time (defaults to current UTC time; injectable for tests).
        window_days: how far back counts as "recent".

    Returns:
        Float in [0, 1]. Higher = more recently/frequently seen (repeated probing).
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=window_days)

    recent_count = 0
    ever_seen = False

    for entry in history:
        if entry.get("pattern_key") != pattern_key:
            continue
        ever_seen = True
        ts = _parse_timestamp(entry.get("timestamp", ""))
        # A timestamp after `now` can't be a real past occurrence — a clock-skew
        # artifact or bad data, not evidence of "very recent" activity. Bound
        # it above as well as below rather than letting it inflate recency.
        if ts is not None and cutoff <= ts <= now:
            recent_count += 1

    if recent_count >= RECENCY_REPEAT_THRESHOLD:
        return RECENCY_HIGH_SCORE
    if recent_count > 0:
        # Linear scale between novel and high for 1-2 recent occurrences
        return min(RECENCY_HIGH_SCORE, RECENCY_NOVEL_SCORE + 0.2 * recent_count)
    if ever_seen:
        return RECENCY_ISOLATED_SCORE
    return RECENCY_NOVEL_SCORE


def _parse_timestamp(ts: str):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


class PriorityScorer:
    """Layer 5: Composite priority scoring across Layers 1-3 + threat recency."""

    def score(
        self,
        anomaly_score: float,
        classification_confidence: float,
        blast_radius_severity: str,
        pattern_key: str = "",
        history: list = None,
        now: datetime = None,
    ) -> PriorityScore:
        """
        Args:
            anomaly_score: Layer 1 output, float in [0, 1].
            classification_confidence: Layer 2 top-match confidence, float in [0, 1].
            blast_radius_severity: Layer 3 severity string (LOW/MEDIUM/HIGH/CRITICAL).
            pattern_key: identifier used to look up recency (e.g. technique ID or
                         vulnerability_type). Empty string yields the "novel" recency score.
            history: optional list of past incidents for recency lookup (see
                     compute_recency_score). Defaults to no history (novel).
            now: reference time for recency (injectable for tests).

        Returns:
            PriorityScore with a 0-100 composite score, P1-P4 tier, a
            human-readable explanation, and the raw/weighted component breakdown.
        """
        anomaly_score = _clamp01(anomaly_score)
        classification_confidence = _clamp01(classification_confidence)
        blast_numeric = SEVERITY_TO_SCORE.get(str(blast_radius_severity or "").upper(), 0.0)
        recency_score = compute_recency_score(history or [], pattern_key, now=now)

        weighted = {
            "anomaly": anomaly_score * WEIGHTS["anomaly"],
            "classification": classification_confidence * WEIGHTS["classification"],
            "blast_radius": blast_numeric * WEIGHTS["blast_radius"],
            "recency": recency_score * WEIGHTS["recency"],
        }
        composite = round(sum(weighted.values()) * 100, 2)
        tier = self._tier_for(composite)

        components = {
            "anomaly": {"raw": anomaly_score, "weight": WEIGHTS["anomaly"], "weighted": round(weighted["anomaly"] * 100, 2)},
            "classification": {"raw": classification_confidence, "weight": WEIGHTS["classification"], "weighted": round(weighted["classification"] * 100, 2)},
            "blast_radius": {"raw": str(blast_radius_severity or "").upper(), "raw_numeric": blast_numeric, "weight": WEIGHTS["blast_radius"], "weighted": round(weighted["blast_radius"] * 100, 2)},
            "recency": {"raw": recency_score, "weight": WEIGHTS["recency"], "weighted": round(weighted["recency"] * 100, 2)},
        }

        explanation = self._build_explanation(composite, tier, components)

        return PriorityScore(score=composite, tier=tier, explanation=explanation, components=components)

    @staticmethod
    def _tier_for(score: float) -> str:
        for threshold, tier in TIER_THRESHOLDS:
            if score >= threshold:
                return tier
        return "P4"

    @staticmethod
    def _build_explanation(score: float, tier: str, components: dict) -> str:
        parts = [
            f"Priority {tier} ({score}/100).",
            f"Anomaly contributed {components['anomaly']['weighted']} pts "
            f"(score {components['anomaly']['raw']:.2f} x {int(components['anomaly']['weight']*100)}%).",
            f"ATT&CK classification contributed {components['classification']['weighted']} pts "
            f"(confidence {components['classification']['raw']:.2f} x {int(components['classification']['weight']*100)}%).",
            f"Blast radius contributed {components['blast_radius']['weighted']} pts "
            f"(severity {components['blast_radius']['raw']} x {int(components['blast_radius']['weight']*100)}%).",
            f"Threat recency contributed {components['recency']['weighted']} pts "
            f"(score {components['recency']['raw']:.2f} x {int(components['recency']['weight']*100)}%).",
        ]
        return " ".join(parts)


def _clamp01(value: float) -> float:
    """Clamp to [0, 1], defaulting to 0.0 for None, NaN, or anything that
    isn't a real number, rather than raising or (via plain min/max, which
    treats NaN as neither greater nor less than anything) silently letting
    NaN through as an inflated 1.0. 0.0 is the conservative choice for a
    *score component*: an unset/invalid signal should contribute nothing to
    the composite rather than being misread as maximal confidence/anomaly,
    which would otherwise inflate a priority score on garbage input. The
    substitution is logged so it stays visible rather than silently masking
    an upstream bug."""
    if value is None or (isinstance(value, float) and value != value):
        logger.warning("Score component was None/NaN — treating as 0.0")
        return 0.0
    try:
        value = float(value)
    except (TypeError, ValueError):
        logger.warning("Score component %r was not numeric — treating as 0.0", value)
        return 0.0
    if value != value:  # float() can itself produce nan from some inputs
        logger.warning("Score component was NaN after coercion — treating as 0.0")
        return 0.0
    return max(0.0, min(1.0, value))
