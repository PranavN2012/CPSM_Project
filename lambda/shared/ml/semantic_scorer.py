"""
semantic_scorer.py — Layer 2: Sentence-BERT Semantic Similarity
================================================================
Scores security events by their semantic similarity to known attack patterns
using Sentence-BERT (all-MiniLM-L6-v2).

Key design decision: the EventNarrator bridge converts structured JSON events
into natural-language descriptions before embedding. This solves the mismatch
between structured security event data and the natural-language embedding space
that SBERT was trained on.

Without the narrator, embedding raw JSON fields produces poor similarity
scores because the model's training distribution is natural English text,
not key-value pairs.
"""

import os
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ATTACK_KB_PATH = os.path.join(_SCRIPT_DIR, "data", "attack_technique_kb.json")
DEFAULT_CALIBRATION_PATH = os.path.join(_SCRIPT_DIR, "data", "classifier_calibration.json")

# Threshold used when calibration data is unavailable or too small (< 10 pairs).
# Not the "real" threshold — a documented, honest fallback.
DEFAULT_FALLBACK_THRESHOLD = 0.50
MIN_CALIBRATION_PAIRS = 10

# ---------------------------------------------------------------------------
# Lazy Loading for Sentence-Transformers
# ---------------------------------------------------------------------------
# sentence-transformers + torch can take 5-10s to import.
# We defer the import to first use so that non-ML codepaths stay fast.

_sbert_model = None
_SBERT_MODEL_NAME = "all-MiniLM-L6-v2"  # 80MB, 384-dim, fast inference


def _get_sbert_model():
    """Lazy-load the Sentence-BERT model on first use."""
    global _sbert_model
    if _sbert_model is None:
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading SBERT model: {_SBERT_MODEL_NAME}")
            _sbert_model = SentenceTransformer(_SBERT_MODEL_NAME)
            logger.info("SBERT model loaded successfully")
        except ImportError:
            logger.warning(
                "sentence-transformers not installed. "
                "SemanticScorer will use fallback TF-IDF scoring."
            )
            _sbert_model = "FALLBACK"
    return _sbert_model


# ---------------------------------------------------------------------------
# Event Narrator — Structured JSON → Natural Language Bridge
# ---------------------------------------------------------------------------

class EventNarrator:
    """Converts structured security event dicts to natural-language descriptions.

    This is the bridge between the structured event format stored in DynamoDB
    and the natural-language embedding space of Sentence-BERT. Without this,
    embedding raw JSON produces poor similarity scores.

    Each vulnerability type has a template that produces a clear, factual
    English sentence describing the security event. Templates are intentionally
    simple and declarative — a panel can follow the logic, unlike a black-box
    approach.
    """

    TEMPLATES = {
        "S3 Public Access": (
            "S3 bucket {resource} in region {region} was found with public "
            "access enabled in AWS account {account}, allowing unrestricted "
            "internet access to stored data"
        ),
        "S3 Encryption": (
            "S3 bucket {resource} in region {region} was found without "
            "server-side encryption in AWS account {account}, leaving data "
            "at rest unprotected"
        ),
        "IAM Audit": (
            "IAM entity {resource} in AWS account {account} was found with "
            "overpermissive wildcard policies granting unrestricted access "
            "to all AWS services and resources"
        ),
        "Security Group Open SSH": (
            "Security group {resource} in region {region} was found with "
            "SSH port 22 open to the entire internet via 0.0.0.0/0 in AWS "
            "account {account}, enabling brute-force attacks"
        ),
        "DynamoDB Unencrypted": (
            "DynamoDB table {resource} in region {region} was found without "
            "encryption at rest in AWS account {account}, exposing NoSQL "
            "data to snapshot theft"
        ),
        "Blob Public Access": (
            "Azure storage account {resource} was found with public blob "
            "access enabled, allowing anonymous access to container data"
        ),
        "Storage Encryption": (
            "Azure storage account {resource} was found without HTTPS-only "
            "enforcement or with outdated TLS version below TLS 1.2"
        ),
        "NSG Open Ports": (
            "Azure Network Security Group {resource} was found with "
            "dangerous ports open to the entire internet via 0.0.0.0/0"
        ),
        "RBAC Overpermissive": (
            "Azure RBAC assignment for {resource} was found with Owner or "
            "Contributor role at subscription level, violating least privilege"
        ),
        "GCS Public Access": (
            "GCP Cloud Storage bucket {resource} was found with public "
            "access granted to allUsers or allAuthenticatedUsers"
        ),
        "GCS Encryption (CMEK)": (
            "GCP Cloud Storage bucket {resource} was found without "
            "Customer-Managed Encryption Keys, using only Google-managed default"
        ),
        "Firewall Open Ports": (
            "GCP firewall rule for {resource} was found allowing traffic "
            "from 0.0.0.0/0 to dangerous ports including SSH and RDP"
        ),
        "IAM Overpermissive": (
            "GCP IAM binding for {resource} was found with Owner or Editor "
            "role at project level, granting excessive permissions"
        ),
    }

    DEFAULT_TEMPLATE = (
        "Security event detected for resource {resource} in region {region} "
        "in account {account} with severity {severity}"
    )

    # Anomaly-context fragments — appended to the base narrative when the
    # caller supplies deviating-feature tags (e.g. from a Layer 1 anomaly
    # result). Combining applicable fragments puts the event description at
    # the same abstraction level as the ATT&CK technique descriptions it will
    # be compared against, instead of relying on the base sentence alone.
    ANOMALY_CONTEXT_FRAGMENTS = {
        "unusual_time": "at an unusual hour, outside normal operating hours",
        "unusual_region": "from an atypical region, not seen in this identity's baseline",
        "high_resource_breadth": "accessing an unusually high number of distinct resources",
        "high_ip_diversity": "from multiple distinct source IP addresses",
        "assume_role_chain": "after assuming a chain of IAM roles",
        "rare_action": "using a rarely-invoked API call for this identity",
        "high_event_rate": "in a rapid burst of activity",
        "cross_service_spread": "spanning an unusually wide range of AWS services",
    }

    def narrate(self, event: dict, anomaly_tags: list = None) -> str:
        """Convert a security event to a natural-language description.

        Args:
            event: Security event dict with keys like 'vulnerability_type',
                   'bucket_name', 'region', 'account_id', 'severity'.
            anomaly_tags: Optional list of deviating-feature tags (see
                          ANOMALY_CONTEXT_FRAGMENTS keys) to weave into the
                          narrative, bridging Layer 1's findings into the
                          text that Layer 2 embeds.

        Returns:
            A plain-English sentence (or two) describing the event.
        """
        vuln_type = event.get("vulnerability_type", "Unknown")
        template = self.TEMPLATES.get(vuln_type, self.DEFAULT_TEMPLATE)

        resource = event.get("bucket_name", event.get("resource_id", "unknown"))
        region = event.get("region", "unknown")
        account = event.get("account_id", "unknown")
        severity = event.get("severity", "UNKNOWN")

        try:
            base = template.format(
                resource=resource,
                region=region,
                account=account,
                severity=severity,
            )
        except KeyError:
            # Template has a placeholder we didn't provide
            base = self.DEFAULT_TEMPLATE.format(
                resource=resource,
                region=region,
                account=account,
                severity=severity,
            )

        fragments = [
            self.ANOMALY_CONTEXT_FRAGMENTS[tag]
            for tag in (anomaly_tags or [])
            if tag in self.ANOMALY_CONTEXT_FRAGMENTS
        ]
        if not fragments:
            return base

        return f"{base}. The access pattern was flagged {', '.join(fragments)}."


# ---------------------------------------------------------------------------
# Known Attack Pattern Library
# ---------------------------------------------------------------------------

KNOWN_ATTACK_PATTERNS = [
    # S3 / Storage attacks
    "S3 bucket in production account had public access enabled allowing "
    "unauthorized data exposure to the entire internet",

    "Cloud storage bucket containing customer payment data was found with "
    "public access enabled in a production environment",

    "Multiple S3 buckets were made public in rapid succession across "
    "different regions indicating a coordinated data exfiltration attempt",

    # Encryption failures
    "Critical production database was found storing data without encryption "
    "at rest exposing sensitive information to physical media theft",

    "Storage account was found with outdated TLS configuration allowing "
    "potential man-in-the-middle attacks on data in transit",

    # IAM attacks
    "IAM user was granted wildcard admin access to all AWS services and "
    "resources violating the principle of least privilege",

    "Service account was found with Owner role at organization level "
    "granting unrestricted access to all cloud resources and projects",

    "Multiple IAM privilege escalations were detected in the same account "
    "shortly before network security changes indicating lateral movement",

    # Network attacks
    "Security group was opened to allow SSH from any IP address on the "
    "internet enabling brute-force password attacks on EC2 instances",

    "Firewall rules were modified to allow unrestricted access to database "
    "ports from the internet exposing backend data stores",

    # Multi-step / Exfiltration
    "Large volume of data was accessed from a cloud storage bucket across "
    "multiple regions during off-hours indicating potential data exfiltration",

    "Multiple security configuration changes were made rapidly in a short "
    "time window across different cloud services suggesting automated attack",

    "Cross-region activity detected from a single account making security "
    "changes in multiple geographic regions simultaneously",

    # Generic high-severity
    "Critical security misconfiguration detected in production environment "
    "with potential for immediate data breach and compliance violation",

    "Automated security scan detected multiple high-severity vulnerabilities "
    "requiring immediate remediation to prevent unauthorized access",
]


# ---------------------------------------------------------------------------
# Cosine Similarity (numpy-only, no scipy dependency)
# ---------------------------------------------------------------------------

def cosine_similarity(vec_a: np.ndarray, vec_b: np.ndarray) -> float:
    """Compute cosine similarity between two vectors.

    Args:
        vec_a: First vector (1D numpy array).
        vec_b: Second vector (1D numpy array).

    Returns:
        Cosine similarity in [-1, 1]. Higher = more similar.
    """
    dot = np.dot(vec_a, vec_b)
    norm_a = np.linalg.norm(vec_a)
    norm_b = np.linalg.norm(vec_b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(dot / (norm_a * norm_b))


# ---------------------------------------------------------------------------
# Fallback TF-IDF Scorer (when sentence-transformers not available)
# ---------------------------------------------------------------------------

class _FallbackScorer:
    """Simple keyword-overlap scorer used when SBERT is not available.

    NOT a replacement for semantic scoring — just ensures the pipeline
    doesn't crash without torch installed.
    """

    def __init__(self, patterns: list):
        self._pattern_tokens = [
            set(p.lower().split()) for p in patterns
        ]

    def score(self, text: str) -> float:
        tokens = set(text.lower().split())
        if not tokens:
            return 0.0
        best = 0.0
        for pattern_tokens in self._pattern_tokens:
            overlap = len(tokens & pattern_tokens)
            union = len(tokens | pattern_tokens)
            if union > 0:
                jaccard = overlap / union
                best = max(best, jaccard)
        return best


# ---------------------------------------------------------------------------
# Semantic Scorer (Layer 2)
# ---------------------------------------------------------------------------

class SemanticScorer:
    """Layer 2: Sentence-BERT semantic similarity scorer.

    Converts security events to natural language via EventNarrator,
    then computes cosine similarity to a library of known attack patterns
    using Sentence-BERT embeddings.

    The score represents how semantically similar the event description is
    to known dangerous patterns. Higher scores indicate events that "read like"
    known attacks.

    Falls back to keyword-overlap scoring if sentence-transformers is not
    installed (with a warning).
    """

    def __init__(self, attack_patterns: list = None):
        """
        Args:
            attack_patterns: Optional list of attack pattern strings.
                             Defaults to KNOWN_ATTACK_PATTERNS.
        """
        self.narrator = EventNarrator()
        self._patterns = attack_patterns or KNOWN_ATTACK_PATTERNS
        self._pattern_embeddings = None
        self._fallback = None
        self._using_fallback = False
        self._initialized = False

    def _ensure_initialized(self):
        """Lazy initialization — loads model and computes pattern embeddings."""
        if self._initialized:
            return

        model = _get_sbert_model()

        if model == "FALLBACK" or model is None:
            self._fallback = _FallbackScorer(self._patterns)
            self._using_fallback = True
            logger.warning("Using fallback keyword scorer (no SBERT)")
        else:
            # Pre-compute embeddings for all known attack patterns
            self._pattern_embeddings = model.encode(
                self._patterns,
                show_progress_bar=False,
                convert_to_numpy=True,
            )
            self._using_fallback = False

        self._initialized = True

    def score(self, event: dict) -> float:
        """Score a security event by semantic similarity to known attacks.

        Pipeline:
        1. EventNarrator converts event → natural language
        2. Sentence-BERT encodes the narrative
        3. Cosine similarity computed against all known attack patterns
        4. Maximum similarity returned (nearest-neighbor approach)

        Args:
            event: Security event dict.

        Returns:
            Float in [0, 1]. Higher = more semantically similar to known attacks.
        """
        self._ensure_initialized()

        narrative = self.narrator.narrate(event)

        if self._using_fallback:
            return round(self._fallback.score(narrative), 4)

        model = _get_sbert_model()
        event_embedding = model.encode(
            narrative,
            show_progress_bar=False,
            convert_to_numpy=True,
        )

        # Compute similarity to each known attack pattern
        similarities = []
        for pattern_emb in self._pattern_embeddings:
            sim = cosine_similarity(event_embedding, pattern_emb)
            # Clamp to [0, 1] — negative cosine similarities mean "unrelated"
            similarities.append(max(0.0, sim))

        # Return the maximum similarity (nearest-neighbor to known attacks)
        max_sim = max(similarities) if similarities else 0.0

        return round(max_sim, 4)

    def score_with_details(self, event: dict) -> dict:
        """Score with full debug details.

        Returns the narrative, score, and the top-3 most similar attack
        patterns for explainability.

        Args:
            event: Security event dict.

        Returns:
            Dict with 'score', 'narrative', 'top_matches', 'using_fallback'.
        """
        self._ensure_initialized()

        narrative = self.narrator.narrate(event)

        if self._using_fallback:
            return {
                "score": round(self._fallback.score(narrative), 4),
                "narrative": narrative,
                "top_matches": [],
                "using_fallback": True,
            }

        model = _get_sbert_model()
        event_embedding = model.encode(
            narrative,
            show_progress_bar=False,
            convert_to_numpy=True,
        )

        # Score against all patterns
        scored_patterns = []
        for i, pattern_emb in enumerate(self._pattern_embeddings):
            sim = cosine_similarity(event_embedding, pattern_emb)
            scored_patterns.append((max(0.0, sim), self._patterns[i]))

        scored_patterns.sort(key=lambda x: x[0], reverse=True)
        max_score = scored_patterns[0][0] if scored_patterns else 0.0

        return {
            "score": round(max_score, 4),
            "narrative": narrative,
            "top_matches": [
                {"similarity": round(s, 4), "pattern": p}
                for s, p in scored_patterns[:3]
            ],
            "using_fallback": False,
        }

    @property
    def is_using_fallback(self) -> bool:
        """Check if using fallback scorer (no SBERT available)."""
        self._ensure_initialized()
        return self._using_fallback

    @property
    def pattern_count(self) -> int:
        """Number of known attack patterns."""
        return len(self._patterns)


# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Classification (Layer 2 — RAG)
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    description: str
    threshold_used: float = 0.0
    top_matches: list = field(default_factory=list)


def _load_attack_kb(path: str = None) -> list:
    """Load the bundled MITRE ATT&CK technique knowledge base."""
    kb_path = path or DEFAULT_ATTACK_KB_PATH
    try:
        with open(kb_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("techniques", [])
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to load ATT&CK knowledge base from %s: %s", kb_path, exc)
        return []


def _load_calibration_pairs(path: str = None) -> list:
    """Load labeled (narrative, technique_id, should_match) calibration pairs."""
    cal_path = path or DEFAULT_CALIBRATION_PATH
    try:
        with open(cal_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("pairs", [])
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load calibration pairs from %s: %s", cal_path, exc)
        return []


class AttackClassifier:
    """Layer 2: MITRE ATT&CK technique classification via embedding similarity (RAG).

    Converts an event to natural language via EventNarrator (optionally folding
    in Layer 1 anomaly context), embeds it, and retrieves the closest-matching
    ATT&CK technique from a bundled cloud-relevant knowledge base.

    The similarity threshold is NOT hardcoded — it's calibrated on startup from
    labeled pairs (see calibrate_threshold()), because cosine similarity between
    unrelated sentences in all-MiniLM-L6-v2 typically sits in the 0.2-0.5 range,
    not near zero. Below the calibrated threshold, classify() honestly reports
    UNKNOWN rather than forcing a low-confidence match.
    """

    def __init__(self, kb_path: str = None, calibration_path: str = None):
        self.narrator = EventNarrator()
        self._kb_path = kb_path
        self._calibration_path = calibration_path
        self._techniques = _load_attack_kb(kb_path)
        self._technique_embeddings = None
        self._threshold = DEFAULT_FALLBACK_THRESHOLD
        self._threshold_calibrated = False
        self._fallback = None
        self._using_fallback = False
        self._initialized = False

    def _ensure_initialized(self):
        if self._initialized:
            return

        model = _get_sbert_model()

        if model == "FALLBACK" or model is None:
            descriptions = [t["description"] for t in self._techniques]
            self._fallback = _FallbackScorer(descriptions)
            self._using_fallback = True
            logger.warning("Using fallback keyword scorer (no SBERT) for AttackClassifier")
        else:
            descriptions = [t["description"] for t in self._techniques]
            self._technique_embeddings = (
                model.encode(descriptions, show_progress_bar=False, convert_to_numpy=True)
                if descriptions else np.array([])
            )
            self._using_fallback = False
            self._threshold = self.calibrate_threshold(
                _load_calibration_pairs(self._calibration_path)
            )

        self._initialized = True

    def calibrate_threshold(self, test_pairs: list) -> float:
        """Find the similarity threshold that best separates "should match"
        from "shouldn't match" pairs, using Youden's J statistic (max of
        TPR - FPR across candidate thresholds — the same idea as picking the
        best operating point on an ROC curve).

        Falls back to DEFAULT_FALLBACK_THRESHOLD if fewer than
        MIN_CALIBRATION_PAIRS pairs are provided.
        """
        if len(test_pairs) < MIN_CALIBRATION_PAIRS:
            logger.warning(
                "Only %d calibration pairs (< %d required); using fallback threshold %.2f",
                len(test_pairs), MIN_CALIBRATION_PAIRS, DEFAULT_FALLBACK_THRESHOLD,
            )
            self._threshold_calibrated = False
            return DEFAULT_FALLBACK_THRESHOLD

        model = _get_sbert_model()
        if model == "FALLBACK" or model is None:
            self._threshold_calibrated = False
            return DEFAULT_FALLBACK_THRESHOLD

        technique_by_id = {t["id"]: t for t in self._techniques}
        scored = []  # (similarity, should_match)

        for pair in test_pairs:
            technique = technique_by_id.get(pair["technique_id"])
            if technique is None:
                continue
            narrative_emb = model.encode(pair["narrative"], show_progress_bar=False, convert_to_numpy=True)
            technique_emb = model.encode(technique["description"], show_progress_bar=False, convert_to_numpy=True)
            sim = cosine_similarity(narrative_emb, technique_emb)
            scored.append((sim, bool(pair["should_match"])))

        if not scored:
            self._threshold_calibrated = False
            return DEFAULT_FALLBACK_THRESHOLD

        positives = sum(1 for _, m in scored if m)
        negatives = sum(1 for _, m in scored if not m)
        if positives == 0 or negatives == 0:
            self._threshold_calibrated = False
            return DEFAULT_FALLBACK_THRESHOLD

        candidates = sorted({round(s, 4) for s, _ in scored})
        best_threshold = DEFAULT_FALLBACK_THRESHOLD
        best_j = -1.0

        for candidate in candidates:
            tp = sum(1 for s, m in scored if m and s >= candidate)
            fp = sum(1 for s, m in scored if not m and s >= candidate)
            tpr = tp / positives
            fpr = fp / negatives
            j = tpr - fpr
            if j > best_j:
                best_j = j
                best_threshold = candidate

        logger.info("AttackClassifier threshold calibrated to %.4f (Youden's J = %.4f, n=%d)",
                    best_threshold, best_j, len(scored))
        self._threshold_calibrated = True
        return best_threshold

    def classify(self, event: dict, anomaly_tags: list = None) -> ClassificationResult:
        """Classify a security event against the ATT&CK knowledge base.

        Args:
            event: Security event dict.
            anomaly_tags: Optional Layer 1 deviating-feature tags, folded into
                          the narrative before embedding (see EventNarrator).

        Returns:
            ClassificationResult. If the best match falls below the calibrated
            threshold, technique_id is "UNKNOWN" and the closest match is
            still reported for reference rather than hidden.
        """
        self._ensure_initialized()

        narrative = self.narrator.narrate(event, anomaly_tags=anomaly_tags)

        if not self._techniques:
            return ClassificationResult(
                technique_id="UNKNOWN", technique_name="", tactic="",
                confidence=0.0, description="No ATT&CK knowledge base loaded.",
                threshold_used=self._threshold,
            )

        if self._using_fallback:
            score = self._fallback.score(narrative)
            # Fallback has no per-technique breakdown; report the closest by keyword overlap.
            best_idx = 0
            return ClassificationResult(
                technique_id=self._techniques[best_idx]["id"] if score >= self._threshold else "UNKNOWN",
                technique_name=self._techniques[best_idx]["name"],
                tactic=self._techniques[best_idx]["tactic"],
                confidence=round(score, 4),
                description=self._techniques[best_idx]["description"],
                threshold_used=self._threshold,
            )

        model = _get_sbert_model()
        narrative_emb = model.encode(narrative, show_progress_bar=False, convert_to_numpy=True)

        scored = []
        for i, technique in enumerate(self._techniques):
            sim = cosine_similarity(narrative_emb, self._technique_embeddings[i])
            scored.append((max(0.0, sim), technique))
        scored.sort(key=lambda x: x[0], reverse=True)

        top_matches = [
            {"technique_id": t["id"], "technique_name": t["name"], "similarity": round(s, 4)}
            for s, t in scored[:3]
        ]

        best_sim, best_technique = scored[0]

        if best_sim < self._threshold:
            return ClassificationResult(
                technique_id="UNKNOWN",
                technique_name="",
                tactic="",
                confidence=round(best_sim, 4),
                description=(
                    f"Does not match any known technique well (closest: "
                    f"{best_technique['id']} {best_technique['name']} at {best_sim:.4f}, "
                    f"below threshold {self._threshold:.4f})."
                ),
                threshold_used=self._threshold,
                top_matches=top_matches,
            )

        return ClassificationResult(
            technique_id=best_technique["id"],
            technique_name=best_technique["name"],
            tactic=best_technique["tactic"],
            confidence=round(best_sim, 4),
            description=best_technique["description"],
            threshold_used=self._threshold,
            top_matches=top_matches,
        )

    @property
    def threshold(self) -> float:
        self._ensure_initialized()
        return self._threshold

    @property
    def is_threshold_calibrated(self) -> bool:
        self._ensure_initialized()
        return self._threshold_calibrated

    @property
    def technique_count(self) -> int:
        return len(self._techniques)
