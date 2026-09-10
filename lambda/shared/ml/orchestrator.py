"""
orchestrator.py — The Agentic Orchestrator
=============================================
The other piece (besides Layer 4's propose/test/revise loop) that earns the
word "agentic": it reads the full context assembled by Layers 1-3, reasons
about it in natural language via an LLM, and outputs a structured decision —
self-directed, not a fixed flowchart. Everything upstream of this (Layers 1,
2, 3, 5) is ML or graph algorithms; this is the piece that decides what to do
about what they found.

Decision flow:
    1. Layer 1 scores the event. Not anomalous -> log and stop.
    2. Anomalous -> Layer 2 (ATT&CK classification) and Layer 3 (blast radius)
       run in parallel (both only need the anomaly result, not each other).
    3. Layer 5 composes a priority score from 1+2+3.
    4. The reasoner (LLM, or a rule-based fallback) reads a structured context
       packet and picks one of: attempt_auto_fix, escalate_to_human,
       gather_more_context, monitor_only — with a rationale.
    5. attempt_auto_fix runs Layer 4 and re-checks blast radius afterward;
       the other three actions just annotate the result for a human/dashboard.

Like Layer 4, the reasoning LLM is pluggable across two providers —
GroqReasoner (GROQ_API_KEY + `groq` package) and GeminiReasoner
(GEMINI_API_KEY + google-generativeai) — auto-selected the same way as
PolicyAgent's LLM client (Groq preferred if both are set; override with
LLM_PROVIDER=gemini|groq), falling back to RuleBasedReasoner otherwise or on
any call failure. The whole pipeline runs and is testable without network
access either way. Keys can live in a project-root .env file (see
.env.example) instead of being exported by hand.
"""

import os
import re
import json
import logging
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ml.anomaly_detector import AnomalyDetector, FEATURE_NAMES
from ml.semantic_scorer import AttackClassifier, ClassificationResult
from ml.blast_radius import InfraGraph, BlastRadiusResult
from ml.priority_scorer import PriorityScorer, PriorityScore
from ml.policy_agent import PolicyAgent, PolicyDraft
from ml.env_loader import load_dotenv_once

logger = logging.getLogger(__name__)

GEMINI_MODEL_NAME = "gemini-2.0-flash"
GROQ_MODEL_NAME = "openai/gpt-oss-120b"


def _build_reasoning_prompt(context: dict) -> str:
    return "\n".join([
        "You are a cloud security triage agent. Given the context below, choose exactly "
        f"one action from this list: {list(AVAILABLE_ACTIONS)}.",
        "Respond with ONLY a JSON object with keys \"action\" and \"rationale\". "
        "No prose, no markdown fences.",
        f"Context: {json.dumps(context)}",
    ])


def _parse_reasoning_response(text: str) -> dict:
    cleaned = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    data = json.loads(cleaned)
    if data.get("action") not in AVAILABLE_ACTIONS:
        raise ValueError(f"LLM returned an invalid action: {data.get('action')!r}")
    if "rationale" not in data:
        raise ValueError("LLM response missing required key: rationale")
    return data

# Layer 1 doesn't ship a calibrated anomaly/not-anomalous cutoff the way
# Layer 2's threshold does (Youden's J over labeled pairs) — there's no
# labeled anomaly/normal dataset for it to calibrate against. This value is
# empirically anchored instead: scoring the real event population produced
# by scripts/simulate-attacks.py showed scores clustering in 0.40-0.52, with
# the largest natural gap (0.453 -> 0.468) separating the CRITICAL/HIGH
# findings from LOW/MEDIUM ones. 0.55 (the original placeholder) sat above
# every real score observed and flagged nothing — not useful as a cutoff.
# Still a placeholder, not a rigorous calibration — just a reasoned one.
ANOMALY_THRESHOLD = 0.46

AVAILABLE_ACTIONS = (
    "attempt_auto_fix",
    "escalate_to_human",
    "gather_more_context",
    "monitor_only",
)


@dataclass
class OrchestratorResult:
    event: dict
    is_anomalous: bool
    anomaly_score: float = 0.0
    deviating_features: list = field(default_factory=list)
    classification: ClassificationResult = None
    blast_radius: BlastRadiusResult = None
    priority: PriorityScore = None
    decision: str = "monitor_only"
    rationale: str = ""
    policy_draft: PolicyDraft = None
    post_fix_blast_radius: BlastRadiusResult = None


def _infer_deviating_tags(feature_vector: dict) -> list:
    """Map Layer 1's raw feature vector to the anomaly-context tag vocabulary
    shared with Layer 2's EventNarrator (see semantic_scorer.py).

    Only tags that Layer 1's current 10-feature set can actually justify are
    derived here (unusual_time, unusual_region, high_event_rate). The doc's
    remaining tags (high_ip_diversity, assume_role_chain, rare_action,
    cross_service_spread, high_resource_breadth) need features Layer 1
    doesn't compute yet (source IP diversity, role-chain depth, per-role
    resource breadth) — a known, stated gap rather than a silent omission.
    """
    tags = []

    hour = feature_vector.get("hour_of_day", 12)
    if hour < 6 or hour >= 22:
        tags.append("unusual_time")

    if feature_vector.get("cross_region_flag", 0):
        tags.append("unusual_region")

    if feature_vector.get("account_frequency_1h", 0) >= 5:
        tags.append("high_event_rate")

    return tags


# ---------------------------------------------------------------------------
# Pluggable reasoning interface
# ---------------------------------------------------------------------------

class Reasoner(ABC):
    @abstractmethod
    def decide(self, context: dict) -> dict:
        """Return {"action": one of AVAILABLE_ACTIONS, "rationale": str}."""
        raise NotImplementedError


class RuleBasedReasoner(Reasoner):
    """Deterministic fallback used when no LLM is configured or a call fails.

    Not a substitute for the LLM's judgment — a documented, conservative
    decision tree so the orchestrator always produces a decision.
    """

    def decide(self, context: dict) -> dict:
        blast = context.get("blast_radius", {})
        severity = blast.get("severity", "LOW")
        classification = context.get("classification", {})
        has_known_technique = classification.get("technique") not in (None, "UNKNOWN", "")
        tier = context.get("priority", {}).get("tier", "P4")
        can_auto_fix = bool(context.get("can_auto_fix"))

        if severity == "CRITICAL" and has_known_technique and tier == "P1":
            if can_auto_fix:
                return {
                    "action": "attempt_auto_fix",
                    "rationale": (
                        f"CRITICAL blast radius with a confidently classified technique "
                        f"({classification.get('technique')}) and P1 priority — attempting "
                        f"an automated fix rather than waiting on a human."
                    ),
                }
            return {
                "action": "escalate_to_human",
                "rationale": (
                    "CRITICAL blast radius and P1 priority, but no policy-fix context was "
                    "supplied for this incident — escalating instead of guessing at a fix."
                ),
            }

        if severity in ("CRITICAL", "HIGH") or tier in ("P1", "P2"):
            return {
                "action": "escalate_to_human",
                "rationale": (
                    f"Blast radius severity {severity} / priority {tier} warrants human "
                    f"review before any automated action is taken."
                ),
            }

        if not has_known_technique:
            return {
                "action": "gather_more_context",
                "rationale": (
                    "The behavior doesn't match a known ATT&CK technique and impact is "
                    "limited so far — worth watching for a repeat before deciding more."
                ),
            }

        return {
            "action": "monitor_only",
            "rationale": "Low blast radius and low priority — logged for the record, no action needed.",
        }


class GeminiReasoner(Reasoner):
    """LLM reasoning over the full context packet, via Gemini `gemini-2.0-flash`."""

    def __init__(self, api_key: str = None):
        load_dotenv_once()
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")

    def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            import google.generativeai  # noqa: F401
            return True
        except ImportError:
            return False

    def decide(self, context: dict) -> dict:
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured")

        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise RuntimeError("google-generativeai package is not installed") from exc

        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        prompt = _build_reasoning_prompt(context)
        response = model.generate_content(prompt, generation_config={"temperature": 0})
        return _parse_reasoning_response(response.text)

    # Kept as instance methods for backward compatibility with existing callers/tests.
    _build_prompt = staticmethod(_build_reasoning_prompt)
    _parse_response = staticmethod(_parse_reasoning_response)


class GroqReasoner(Reasoner):
    """LLM reasoning over the full context packet, via Groq's OpenAI-compatible
    chat API. Requires GROQ_API_KEY (env var, .env file, or passed explicitly)
    and the `groq` package."""

    def __init__(self, api_key: str = None, model: str = None):
        load_dotenv_once()
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.model = model or os.environ.get("GROQ_MODEL", GROQ_MODEL_NAME)

    def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            import groq  # noqa: F401
            return True
        except ImportError:
            return False

    def decide(self, context: dict) -> dict:
        if not self.api_key:
            raise RuntimeError("GROQ_API_KEY is not configured")

        try:
            from groq import Groq
        except ImportError as exc:
            raise RuntimeError("groq package is not installed") from exc

        client = Groq(api_key=self.api_key)
        prompt = _build_reasoning_prompt(context)
        response = client.chat.completions.create(
            model=self.model,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        return _parse_reasoning_response(response.choices[0].message.content)


# ---------------------------------------------------------------------------
# ThreatOrchestrator
# ---------------------------------------------------------------------------

class ThreatOrchestrator:
    def __init__(
        self,
        anomaly_detector: AnomalyDetector = None,
        attack_classifier: AttackClassifier = None,
        infra_graph: InfraGraph = None,
        priority_scorer: PriorityScorer = None,
        policy_agent: PolicyAgent = None,
        reasoner: Reasoner = None,
        anomaly_threshold: float = ANOMALY_THRESHOLD,
    ):
        self.anomaly_detector = anomaly_detector or AnomalyDetector().fit()
        self.attack_classifier = attack_classifier or AttackClassifier()
        self.infra_graph = infra_graph or InfraGraph().build_from_seed()
        self.priority_scorer = priority_scorer or PriorityScorer()
        self.policy_agent = policy_agent or PolicyAgent()
        self.reasoner = reasoner or self._default_reasoner()
        self.anomaly_threshold = anomaly_threshold

    @staticmethod
    def _default_reasoner() -> Reasoner:
        load_dotenv_once()
        provider = os.environ.get("LLM_PROVIDER", "").lower()
        candidates = {"groq": GroqReasoner, "gemini": GeminiReasoner}
        order = [provider] if provider in candidates else ["groq", "gemini"]
        order += [name for name in candidates if name not in order]

        for name in order:
            reasoner = candidates[name]()
            if reasoner.is_available():
                logger.info("ThreatOrchestrator using %s reasoner", name)
                return reasoner

        logger.info("No LLM API key configured — ThreatOrchestrator using RuleBasedReasoner")
        return RuleBasedReasoner()

    def process_event(self, event: dict, history: list = None) -> OrchestratorResult:
        anomaly_score = self.anomaly_detector.score(event)
        is_anomalous = anomaly_score >= self.anomaly_threshold

        if not is_anomalous:
            logger.info("Event scored %.4f (< %.2f threshold) — not anomalous, logging only",
                        anomaly_score, self.anomaly_threshold)
            return OrchestratorResult(event=event, is_anomalous=False, anomaly_score=anomaly_score,
                                       decision="monitor_only", rationale="Below the anomaly threshold.")

        feature_vector = self.anomaly_detector.get_feature_vector(event)
        deviating_features = _infer_deviating_tags(feature_vector)

        classification, blast_radius = self._run_layers_2_and_3_in_parallel(event, deviating_features)

        priority = self.priority_scorer.score(
            anomaly_score=anomaly_score,
            classification_confidence=classification.confidence,
            blast_radius_severity=blast_radius.severity,
            pattern_key=classification.technique_id,
            history=history or [],
        )

        context = self._build_context(event, anomaly_score, deviating_features, classification, blast_radius, priority)

        try:
            decision = self.reasoner.decide(context)
        except Exception as exc:
            logger.warning("Reasoner failed (%s); falling back to RuleBasedReasoner", exc)
            decision = RuleBasedReasoner().decide(context)

        result = OrchestratorResult(
            event=event, is_anomalous=True, anomaly_score=anomaly_score,
            deviating_features=deviating_features, classification=classification,
            blast_radius=blast_radius, priority=priority,
            decision=decision["action"], rationale=decision["rationale"],
        )

        if decision["action"] == "attempt_auto_fix":
            self._execute_auto_fix(event, blast_radius, result)

        return result

    def _run_layers_2_and_3_in_parallel(self, event: dict, deviating_features: list):
        entry_point = event.get("principal") or event.get("role_name") or event.get("account_id")
        resource_id = event.get("bucket_name")

        with ThreadPoolExecutor(max_workers=2) as pool:
            classification_future = pool.submit(self.attack_classifier.classify, event, deviating_features)
            blast_radius_future = pool.submit(self._safe_blast_radius, entry_point, resource_id)
            classification = classification_future.result()
            blast_radius = blast_radius_future.result()

        return classification, blast_radius

    def _safe_blast_radius(self, entry_point: str, resource_id: str = None) -> BlastRadiusResult:
        """Prefers a real identity-based BFS traversal when the event names a
        known IAM identity (simulate_blast_radius — unchanged, still the
        function verified against an independent oracle). Falls back to a
        direct resource-exposure check (resource_exposure_severity) when the
        event instead names a specific resource that's a known node in the
        graph but isn't an identity to traverse from — e.g. a live S3 Public
        Access finding whose bucket name happens to match a real graph node.
        This is what lets live events (not just the 4 crafted demo
        scenarios) get a real, differentiated severity instead of always
        defaulting to LOW."""
        if entry_point and entry_point in self.infra_graph.nodes:
            return self.infra_graph.simulate_blast_radius(entry_point)
        if resource_id and resource_id in self.infra_graph.nodes:
            return self.infra_graph.resource_exposure_severity(resource_id)
        logger.info("No known graph entry point or resource for this event — blast radius defaults to LOW")
        return BlastRadiusResult(entry_point=entry_point or resource_id or "unknown", severity="LOW")

    @staticmethod
    def _build_context(event, anomaly_score, deviating_features, classification, blast_radius, priority) -> dict:
        return {
            "anomaly_score": anomaly_score,
            "deviating_features": deviating_features,
            "classification": {
                "technique": classification.technique_id,
                "technique_name": classification.technique_name,
                "confidence": classification.confidence,
                "tactic": classification.tactic,
            },
            "blast_radius": {
                "critical_resources_reached": len(blast_radius.critical_resources_reached),
                "max_depth": blast_radius.max_depth,
                "severity": blast_radius.severity,
            },
            "priority": {"score": priority.score, "tier": priority.tier},
            "can_auto_fix": bool(event.get("policy_fix_context")),
            "available_actions": list(AVAILABLE_ACTIONS),
        }

    def _execute_auto_fix(self, event: dict, blast_radius: BlastRadiusResult, result: OrchestratorResult) -> None:
        incident = event.get("policy_fix_context")
        if not incident:
            result.decision = "escalate_to_human"
            result.rationale += " (No policy-fix context supplied — escalated instead of guessing.)"
            return

        draft = self.policy_agent.revise_and_retry(incident, blast_radius={
            "severity": blast_radius.severity,
            "critical_resources_reached": blast_radius.critical_resources_reached,
        })
        result.policy_draft = draft

        if draft.test_passed:
            # Full "re-run Layer 3 to verify" would require re-deriving graph edges
            # from draft.policy_json via build_from_iam_policies() against a live
            # role -> resource mapping; the hand-built seed graph doesn't track
            # per-role policy documents, so that loop isn't wired for the demo.
            # draft.test_passed (from PolicyEvaluator) is the safety signal instead.
            result.post_fix_blast_radius = None
        else:
            # All revise_and_retry attempts failed the sandbox test — the draft
            # is not safe to treat as an applied fix. Downgrade the decision so
            # anything consuming `result.decision` (dashboards, an eval harness)
            # doesn't count a failed auto-fix as a successful one; the failed
            # draft and its errors are still attached for a human to review.
            result.decision = "escalate_to_human"
            result.rationale += (
                f" (Auto-fix attempted but failed sandbox testing after "
                f"{draft.attempt_number} attempt(s): {'; '.join(draft.errors)} — escalated instead.)"
            )
