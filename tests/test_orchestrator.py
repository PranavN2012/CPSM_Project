"""
test_orchestrator.py — Tests for the Agentic Orchestrator
=============================================================
Covers the not-anomalous short-circuit, the parallel Layer 2/3 execution,
context-packet assembly, the RuleBasedReasoner decision tree, GeminiReasoner
availability/parsing, reasoner-failure fallback, and the attempt_auto_fix path
(including the "no policy-fix context supplied" escalation).
"""

import sys
import os

import pytest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
sys.path.insert(0, os.path.join(PROJECT_DIR, "lambda", "shared"))

from ml.orchestrator import (
    ThreatOrchestrator,
    OrchestratorResult,
    Reasoner,
    RuleBasedReasoner,
    GeminiReasoner,
    GroqReasoner,
    AVAILABLE_ACTIONS,
    ANOMALY_THRESHOLD,
    _infer_deviating_tags,
)
from ml.anomaly_detector import AnomalyDetector
from ml.semantic_scorer import AttackClassifier
from ml.blast_radius import InfraGraph
from ml.priority_scorer import PriorityScorer
from ml.policy_agent import PolicyAgent, RuleBasedPolicyDrafter


def _disable_all_llm_keys(monkeypatch):
    """See tests/test_policy_agent.py::_disable_all_llm_keys for why delenv
    alone isn't reliable once a real .env exists on disk."""
    monkeypatch.setattr("ml.orchestrator.load_dotenv_once", lambda: None)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


def _normal_event():
    return {
        "timestamp": "2026-06-12T14:30:00Z",
        "vulnerability_type": "S3 Public Access",
        "severity": "MEDIUM",
        "bucket_name": "dev-test-bucket",
        "account_id": "123456789012",
        "region": "us-east-1",
        "status": "REMEDIATED",
    }


def _suspicious_event():
    return {
        "timestamp": "2026-06-12T03:00:00Z",
        "vulnerability_type": "IAM Audit",
        "severity": "CRITICAL",
        "bucket_name": "wildcard-admin-policy",
        "account_id": "999999999999",
        "region": "ap-southeast-1",
        "status": "IAM_OVERPERMISSIVE",
        "principal": "ci-deploy-role",
    }


def _build_orchestrator(reasoner=None, policy_agent=None):
    """A cheaply-constructed orchestrator reusing one shared AttackClassifier
    across tests (SBERT load is the expensive part) — pytest fixtures would
    also work, but module-level caching in semantic_scorer already handles this."""
    return ThreatOrchestrator(
        anomaly_detector=AnomalyDetector().fit(),
        attack_classifier=AttackClassifier(),
        infra_graph=InfraGraph().build_from_seed(),
        priority_scorer=PriorityScorer(),
        policy_agent=policy_agent or PolicyAgent(llm_client=RuleBasedPolicyDrafter()),
        reasoner=reasoner,
    )


# ---------------------------------------------------------------------------
# _infer_deviating_tags
# ---------------------------------------------------------------------------

class TestInferDeviatingTags:
    def test_off_hours_tagged_unusual_time(self):
        tags = _infer_deviating_tags({"hour_of_day": 3})
        assert "unusual_time" in tags

    def test_business_hours_not_tagged(self):
        tags = _infer_deviating_tags({"hour_of_day": 14})
        assert "unusual_time" not in tags

    def test_cross_region_flag_tagged(self):
        tags = _infer_deviating_tags({"cross_region_flag": 1})
        assert "unusual_region" in tags

    def test_high_account_frequency_tagged(self):
        tags = _infer_deviating_tags({"account_frequency_1h": 6})
        assert "high_event_rate" in tags

    def test_empty_features_yields_no_tags(self):
        assert _infer_deviating_tags({}) == []


# ---------------------------------------------------------------------------
# RuleBasedReasoner
# ---------------------------------------------------------------------------

class TestRuleBasedReasoner:
    def setup_method(self):
        self.reasoner = RuleBasedReasoner()

    def test_critical_with_known_technique_and_fix_context_attempts_auto_fix(self):
        context = {
            "blast_radius": {"severity": "CRITICAL"},
            "classification": {"technique": "T1098"},
            "priority": {"tier": "P1"},
            "can_auto_fix": True,
        }
        decision = self.reasoner.decide(context)
        assert decision["action"] == "attempt_auto_fix"

    def test_critical_without_fix_context_escalates(self):
        context = {
            "blast_radius": {"severity": "CRITICAL"},
            "classification": {"technique": "T1098"},
            "priority": {"tier": "P1"},
            "can_auto_fix": False,
        }
        decision = self.reasoner.decide(context)
        assert decision["action"] == "escalate_to_human"

    def test_high_severity_escalates(self):
        context = {
            "blast_radius": {"severity": "HIGH"},
            "classification": {"technique": "T1530"},
            "priority": {"tier": "P2"},
            "can_auto_fix": False,
        }
        decision = self.reasoner.decide(context)
        assert decision["action"] == "escalate_to_human"

    def test_unknown_technique_low_impact_gathers_more_context(self):
        context = {
            "blast_radius": {"severity": "LOW"},
            "classification": {"technique": "UNKNOWN"},
            "priority": {"tier": "P4"},
            "can_auto_fix": False,
        }
        decision = self.reasoner.decide(context)
        assert decision["action"] == "gather_more_context"

    def test_low_everything_monitors_only(self):
        context = {
            "blast_radius": {"severity": "LOW"},
            "classification": {"technique": "T1530"},
            "priority": {"tier": "P4"},
            "can_auto_fix": False,
        }
        decision = self.reasoner.decide(context)
        assert decision["action"] == "monitor_only"

    def test_decision_always_has_rationale(self):
        for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            context = {"blast_radius": {"severity": severity}, "classification": {"technique": "T1530"},
                       "priority": {"tier": "P3"}, "can_auto_fix": False}
            decision = self.reasoner.decide(context)
            assert decision["action"] in AVAILABLE_ACTIONS
            assert decision["rationale"]


# ---------------------------------------------------------------------------
# GeminiReasoner — availability and parsing (no real network calls)
# ---------------------------------------------------------------------------

class TestGeminiReasoner:
    def test_unavailable_without_api_key(self, monkeypatch):
        _disable_all_llm_keys(monkeypatch)
        assert not GeminiReasoner().is_available()

    def test_decide_raises_without_api_key(self, monkeypatch):
        _disable_all_llm_keys(monkeypatch)
        with pytest.raises(RuntimeError):
            GeminiReasoner().decide({})

    def test_parse_response_valid_action(self):
        raw = '{"action": "escalate_to_human", "rationale": "high risk"}'
        parsed = GeminiReasoner._parse_response(raw)
        assert parsed["action"] == "escalate_to_human"

    def test_parse_response_strips_fences(self):
        raw = '```json\n{"action": "monitor_only", "rationale": "fine"}\n```'
        parsed = GeminiReasoner._parse_response(raw)
        assert parsed["action"] == "monitor_only"

    def test_parse_response_invalid_action_raises(self):
        raw = '{"action": "launch_missiles", "rationale": "oops"}'
        with pytest.raises(ValueError):
            GeminiReasoner._parse_response(raw)

    def test_parse_response_missing_rationale_raises(self):
        raw = '{"action": "monitor_only"}'
        with pytest.raises(ValueError):
            GeminiReasoner._parse_response(raw)


# ---------------------------------------------------------------------------
# ThreatOrchestrator — end-to-end (rule-based reasoner, no network)
# ---------------------------------------------------------------------------

class TestOrchestratorDefaults:
    def test_defaults_to_rule_based_reasoner_without_api_key(self, monkeypatch):
        _disable_all_llm_keys(monkeypatch)
        orchestrator = _build_orchestrator()
        assert isinstance(orchestrator.reasoner, RuleBasedReasoner)

    def test_prefers_groq_when_both_keys_present(self, monkeypatch):
        monkeypatch.setattr("ml.orchestrator.load_dotenv_once", lambda: None)
        monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key")
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        orchestrator = _build_orchestrator()
        assert isinstance(orchestrator.reasoner, GroqReasoner)


class TestProcessEvent:
    @classmethod
    def setup_class(cls):
        cls.orchestrator = _build_orchestrator()

    def test_normal_event_short_circuits_as_not_anomalous_or_flows_through(self):
        """Whichever way the raw Isolation Forest score lands for this benign
        event, the result must be internally consistent."""
        result = self.orchestrator.process_event(_normal_event())
        assert isinstance(result, OrchestratorResult)
        if not result.is_anomalous:
            assert result.decision == "monitor_only"
            assert result.classification is None
            assert result.blast_radius is None
        else:
            assert result.classification is not None
            assert result.blast_radius is not None

    def test_result_always_has_valid_decision(self):
        result = self.orchestrator.process_event(_suspicious_event())
        assert result.decision in AVAILABLE_ACTIONS

    def test_anomalous_event_populates_all_layer_outputs(self):
        orchestrator = _build_orchestrator()
        # Force anomalous path deterministically regardless of the raw score.
        orchestrator.anomaly_threshold = -1.0
        result = orchestrator.process_event(_suspicious_event())

        assert result.is_anomalous
        assert result.classification is not None
        assert result.blast_radius is not None
        assert result.priority is not None
        assert result.blast_radius.entry_point == "ci-deploy-role"

    def test_unknown_entry_point_degrades_to_low_blast_radius_without_crashing(self):
        orchestrator = _build_orchestrator()
        orchestrator.anomaly_threshold = -1.0
        event = _suspicious_event()
        event["principal"] = "no-such-role-in-graph"
        result = orchestrator.process_event(event)
        assert result.blast_radius.severity == "LOW"

    def test_reasoner_failure_falls_back_to_rule_based(self):
        class AlwaysFailsReasoner(Reasoner):
            def decide(self, context):
                raise RuntimeError("simulated reasoner outage")

        orchestrator = _build_orchestrator(reasoner=AlwaysFailsReasoner())
        orchestrator.anomaly_threshold = -1.0
        result = orchestrator.process_event(_suspicious_event())
        assert result.decision in AVAILABLE_ACTIONS  # RuleBasedReasoner still produced a valid decision

    def test_attempt_auto_fix_without_policy_context_escalates_instead(self):
        class AlwaysAutoFixReasoner(Reasoner):
            def decide(self, context):
                return {"action": "attempt_auto_fix", "rationale": "test forcing auto-fix"}

        orchestrator = _build_orchestrator(reasoner=AlwaysAutoFixReasoner())
        orchestrator.anomaly_threshold = -1.0
        event = _suspicious_event()  # no policy_fix_context
        result = orchestrator.process_event(event)

        assert result.decision == "escalate_to_human"
        assert result.policy_draft is None

    def test_attempt_auto_fix_with_policy_context_runs_layer_4(self):
        class AlwaysAutoFixReasoner(Reasoner):
            def decide(self, context):
                return {"action": "attempt_auto_fix", "rationale": "test forcing auto-fix"}

        orchestrator = _build_orchestrator(
            reasoner=AlwaysAutoFixReasoner(),
            policy_agent=PolicyAgent(llm_client=RuleBasedPolicyDrafter()),
        )
        orchestrator.anomaly_threshold = -1.0
        event = _suspicious_event()
        event["policy_fix_context"] = {
            "current_policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            "offending_action": "iam:CreatePolicy",
            "offending_resource": "*",
        }
        result = orchestrator.process_event(event)

        assert result.decision == "attempt_auto_fix"
        assert result.policy_draft is not None
        assert result.policy_draft.test_passed

    def test_auto_fix_that_fails_sandbox_test_escalates_instead(self):
        """Regression: if every revise_and_retry attempt fails PolicyEvaluator,
        the orchestrator used to leave result.decision as "attempt_auto_fix"
        even though no safe fix was produced — misleading for anything reading
        `decision` directly (a dashboard, an eval harness) into believing the
        incident was auto-remediated. It must downgrade to escalate_to_human,
        matching the "no fix context" escalation path above."""
        class AlwaysAutoFixReasoner(Reasoner):
            def decide(self, context):
                return {"action": "attempt_auto_fix", "rationale": "test forcing auto-fix"}

        class AlwaysFailingDrafter:
            """A drafter whose output never blocks the offending action, so
            PolicyEvaluator fails it on every attempt."""

            def draft_policy_fix(self, incident, blast_radius, previous_attempt=None):
                return {
                    "policy_json": incident.get("current_policy") or {"Statement": []},
                    "description": "does nothing",
                    "rationale": "deliberately ineffective for this test",
                }

        orchestrator = _build_orchestrator(
            reasoner=AlwaysAutoFixReasoner(),
            policy_agent=PolicyAgent(llm_client=AlwaysFailingDrafter()),
        )
        orchestrator.anomaly_threshold = -1.0
        event = _suspicious_event()
        event["policy_fix_context"] = {
            "current_policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            "offending_action": "iam:CreatePolicy",
            "offending_resource": "*",
        }
        result = orchestrator.process_event(event)

        assert result.decision == "escalate_to_human"
        assert result.policy_draft is not None
        assert not result.policy_draft.test_passed
        assert "failed sandbox testing" in result.rationale
