"""
test_policy_agent.py — Tests for Layer 4: Autonomous Policy-Writing Agent
============================================================================
Covers the PolicyEvaluator sandbox (Allow/Deny/wildcard resolution), the
RuleBasedPolicyDrafter fallback, GeminiLLMClient availability/fallback
behavior (no real network calls — GEMINI_API_KEY is unset in this env), and
the full propose -> test -> revise loop including its failure path.
"""

import sys
import os

import pytest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
sys.path.insert(0, os.path.join(PROJECT_DIR, "lambda", "shared"))

from ml.policy_agent import (
    PolicyAgent,
    PolicyEvaluator,
    PolicyDraft,
    TestResult,
    LLMClient,
    RuleBasedPolicyDrafter,
    GeminiLLMClient,
    GroqLLMClient,
    DEFAULT_MAX_ATTEMPTS,
)


def _disable_all_llm_keys(monkeypatch):
    """Simulate an environment with no LLM provider configured at all.

    Deleting env vars alone isn't enough once a real .env exists on disk:
    env_loader.load_dotenv_once() only reads the file once per process, so
    whether delenv "sticks" depends on whether that one-time load already
    happened earlier in the test session — order-dependent and flaky. Patching
    load_dotenv_once to a no-op in both modules that import it removes that
    dependency entirely.
    """
    monkeypatch.setattr("ml.policy_agent.load_dotenv_once", lambda: None)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


# ---------------------------------------------------------------------------
# PolicyEvaluator
# ---------------------------------------------------------------------------

class TestPolicyEvaluator:
    def setup_method(self):
        self.evaluator = PolicyEvaluator()

    def test_simple_allow(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket"}]}
        assert self.evaluator.evaluate(policy, "s3:GetObject", "arn:aws:s3:::my-bucket")

    def test_no_matching_statement_denies_by_default(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::other"}]}
        assert not self.evaluator.evaluate(policy, "s3:GetObject", "arn:aws:s3:::my-bucket")

    def test_wildcard_action_matches(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        assert self.evaluator.evaluate(policy, "s3:DeleteObject", "arn:aws:s3:::any-bucket")

    def test_wildcard_resource_prefix_matches(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::prod-*"}]}
        assert self.evaluator.evaluate(policy, "s3:GetObject", "arn:aws:s3:::prod-data-lake")
        assert not self.evaluator.evaluate(policy, "s3:GetObject", "arn:aws:s3:::dev-bucket")

    def test_explicit_deny_overrides_allow_regardless_of_order(self):
        policy = {"Statement": [
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::prod-*"},
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        ]}
        assert not self.evaluator.evaluate(policy, "s3:DeleteObject", "arn:aws:s3:::prod-bucket")
        assert self.evaluator.evaluate(policy, "s3:GetObject", "arn:aws:s3:::prod-bucket")

    def test_multiple_statements_evaluated_together(self):
        policy = {"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket-a"},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::bucket-b"},
        ]}
        assert self.evaluator.evaluate(policy, "s3:GetObject", "arn:aws:s3:::bucket-a")
        assert self.evaluator.evaluate(policy, "s3:PutObject", "arn:aws:s3:::bucket-b")
        assert not self.evaluator.evaluate(policy, "s3:PutObject", "arn:aws:s3:::bucket-a")

    def test_single_statement_dict_not_list(self):
        policy = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
        assert self.evaluator.evaluate(policy, "s3:GetObject", "anything")

    def test_empty_policy_denies_everything(self):
        assert not self.evaluator.evaluate({"Statement": []}, "s3:GetObject", "anything")


# ---------------------------------------------------------------------------
# RuleBasedPolicyDrafter
# ---------------------------------------------------------------------------

class TestRuleBasedPolicyDrafter:
    def setup_method(self):
        self.drafter = RuleBasedPolicyDrafter()
        self.incident = {
            "current_policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
            },
            "offending_action": "s3:DeleteBucket",
            "offending_resource": "arn:aws:s3:::prod-data-lake-raw",
        }

    def test_appends_explicit_deny(self):
        result = self.drafter.draft_policy_fix(self.incident, {})
        statements = result["policy_json"]["Statement"]
        assert any(
            s["Effect"] == "Deny" and s["Action"] == "s3:DeleteBucket"
            and s["Resource"] == "arn:aws:s3:::prod-data-lake-raw"
            for s in statements
        )

    def test_preserves_original_statements(self):
        result = self.drafter.draft_policy_fix(self.incident, {})
        statements = result["policy_json"]["Statement"]
        assert any(s["Effect"] == "Allow" and s["Action"] == "s3:*" for s in statements)

    def test_does_not_mutate_input_policy(self):
        original_len = len(self.incident["current_policy"]["Statement"])
        self.drafter.draft_policy_fix(self.incident, {})
        assert len(self.incident["current_policy"]["Statement"]) == original_len

    def test_missing_current_policy_defaults_to_empty(self):
        incident = {"offending_action": "s3:*", "offending_resource": "*"}
        result = self.drafter.draft_policy_fix(incident, {})
        assert result["policy_json"]["Statement"]

    def test_description_and_rationale_present(self):
        result = self.drafter.draft_policy_fix(self.incident, {})
        assert result["description"]
        assert result["rationale"]


# ---------------------------------------------------------------------------
# GeminiLLMClient — availability and graceful failure (no real network calls)
# ---------------------------------------------------------------------------

class TestGeminiLLMClient:
    def test_unavailable_without_api_key(self, monkeypatch):
        _disable_all_llm_keys(monkeypatch)
        client = GeminiLLMClient()
        assert not client.is_available()

    def test_draft_raises_without_api_key(self, monkeypatch):
        _disable_all_llm_keys(monkeypatch)
        client = GeminiLLMClient()
        with pytest.raises(RuntimeError):
            client.draft_policy_fix({}, {})

    def test_explicit_api_key_marks_available_if_package_installed(self):
        client = GeminiLLMClient(api_key="fake-key-for-test")
        try:
            import google.generativeai  # noqa: F401
            assert client.is_available()
        except ImportError:
            assert not client.is_available()

    def test_parse_response_strips_markdown_fences(self):
        raw = '```json\n{"policy_json": {"Statement": []}, "description": "d", "rationale": "r"}\n```'
        parsed = GeminiLLMClient._parse_response(raw)
        assert parsed["description"] == "d"

    def test_parse_response_missing_key_raises(self):
        raw = '{"policy_json": {}}'
        with pytest.raises(ValueError):
            GeminiLLMClient._parse_response(raw)


# ---------------------------------------------------------------------------
# PolicyAgent — default client selection and LLM-failure fallback
# ---------------------------------------------------------------------------

class TestPolicyAgentDefaults:
    def test_defaults_to_rule_based_without_api_key(self, monkeypatch):
        _disable_all_llm_keys(monkeypatch)
        agent = PolicyAgent()
        assert isinstance(agent.llm_client, RuleBasedPolicyDrafter)

    def test_prefers_groq_when_both_keys_present(self, monkeypatch):
        monkeypatch.setattr("ml.policy_agent.load_dotenv_once", lambda: None)
        monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key")
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        agent = PolicyAgent()
        assert isinstance(agent.llm_client, GroqLLMClient)

    def test_llm_provider_env_var_overrides_preference(self, monkeypatch):
        monkeypatch.setattr("ml.policy_agent.load_dotenv_once", lambda: None)
        monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key")
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
        monkeypatch.setenv("LLM_PROVIDER", "gemini")
        agent = PolicyAgent()
        assert isinstance(agent.llm_client, GeminiLLMClient)

    def test_falls_back_when_llm_client_raises(self):
        class AlwaysFailsClient(LLMClient):
            def draft_policy_fix(self, incident, blast_radius, previous_attempt=None):
                raise RuntimeError("simulated LLM outage")

        agent = PolicyAgent(llm_client=AlwaysFailsClient())
        incident = {
            "current_policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            "offending_action": "s3:DeleteBucket",
            "offending_resource": "arn:aws:s3:::prod-bucket",
        }
        draft = agent.draft_fix(incident)
        assert isinstance(draft, PolicyDraft)
        assert "Deny" in str(draft.policy_json)

    def test_double_encoded_policy_json_string_is_unwrapped(self):
        """Found via eval/layer4b_baseline_comparison_eval.py: an LLM can
        return policy_json as a JSON-encoded string instead of an object
        (double-encoding). Previously this reached PolicyEvaluator.evaluate()
        unchanged and crashed with an unhandled AttributeError the moment it
        called policy_json.get(...). Should unwrap once and produce a normal
        dict-shaped draft."""
        import json as _json

        inner = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}

        class DoubleEncodedClient(LLMClient):
            def draft_policy_fix(self, incident, blast_radius, previous_attempt=None):
                return {"policy_json": _json.dumps(inner), "description": "d", "rationale": "r"}

        agent = PolicyAgent(llm_client=DoubleEncodedClient())
        incident = {
            "current_policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            "offending_action": "s3:DeleteBucket",
            "offending_resource": "arn:aws:s3:::prod-bucket",
        }
        draft = agent.draft_fix(incident)
        assert isinstance(draft.policy_json, dict)
        assert draft.policy_json == inner
        # Must not crash the evaluator either — this is the actual regression.
        result = agent.test_fix(draft, {**incident, "must_still_allow": []})
        assert isinstance(result, TestResult)

    def test_non_dict_non_string_policy_json_falls_back_to_rule_based(self):
        """A policy_json that's neither a dict nor a JSON string at all
        (e.g. the LLM returned null) should fall back to the deterministic
        rule-based drafter rather than crash or silently pass through."""
        class GarbageClient(LLMClient):
            def draft_policy_fix(self, incident, blast_radius, previous_attempt=None):
                return {"policy_json": None, "description": "d", "rationale": "r"}

        agent = PolicyAgent(llm_client=GarbageClient())
        incident = {
            "current_policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            "offending_action": "s3:DeleteBucket",
            "offending_resource": "arn:aws:s3:::prod-bucket",
        }
        draft = agent.draft_fix(incident)
        assert isinstance(draft.policy_json, dict)
        assert "Deny" in str(draft.policy_json)


# ---------------------------------------------------------------------------
# PolicyAgent — propose -> test -> revise loop
# ---------------------------------------------------------------------------

class TestReviseAndRetryLoop:
    def _incident(self):
        return {
            "current_policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
            },
            "offending_action": "s3:DeleteBucket",
            "offending_resource": "arn:aws:s3:::prod-data-lake-raw",
            "must_still_allow": [("s3:GetObject", "arn:aws:s3:::prod-data-lake-raw")],
        }

    def test_rule_based_fix_passes_on_first_attempt(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        agent = PolicyAgent()
        draft = agent.revise_and_retry(self._incident())

        assert draft.test_passed
        assert draft.attempt_number == 1

    def test_test_fix_flags_still_allowed_action(self):
        agent = PolicyAgent(llm_client=RuleBasedPolicyDrafter())
        incident = self._incident()
        unfixed_draft = PolicyDraft(
            policy_json=incident["current_policy"], description="no-op", rationale="none",
        )
        result = agent.test_fix(unfixed_draft, incident)
        assert not result.passed
        assert any("still allows" in e for e in result.errors)

    def test_test_fix_flags_regression(self):
        agent = PolicyAgent(llm_client=RuleBasedPolicyDrafter())
        incident = self._incident()
        over_broad_deny = {
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]
        }
        draft = PolicyDraft(policy_json=over_broad_deny, description="too broad", rationale="oops")
        result = agent.test_fix(draft, incident)
        assert not result.passed
        assert any("regressed" in e for e in result.errors)

    def test_loop_gives_up_after_max_attempts_when_llm_always_fails_the_test(self):
        class AlwaysNoOpClient(LLMClient):
            def draft_policy_fix(self, incident, blast_radius, previous_attempt=None):
                # Never actually fixes anything — the test should always fail.
                return {
                    "policy_json": incident["current_policy"],
                    "description": "no-op draft",
                    "rationale": "intentionally broken for this test",
                }

        agent = PolicyAgent(llm_client=AlwaysNoOpClient())
        draft = agent.revise_and_retry(self._incident(), max_attempts=DEFAULT_MAX_ATTEMPTS)

        assert not draft.test_passed
        assert draft.attempt_number == DEFAULT_MAX_ATTEMPTS
        assert draft.errors

    def test_previous_attempt_context_passed_to_next_draft(self):
        seen_previous_attempts = []

        class RecordingClient(LLMClient):
            def draft_policy_fix(self, incident, blast_radius, previous_attempt=None):
                seen_previous_attempts.append(previous_attempt)
                if previous_attempt is None:
                    # First attempt: deliberately broken (no-op).
                    return {"policy_json": incident["current_policy"], "description": "d", "rationale": "r"}
                # Second attempt: fix it using the rule-based patch.
                return RuleBasedPolicyDrafter().draft_policy_fix(incident, blast_radius)

        agent = PolicyAgent(llm_client=RecordingClient())
        draft = agent.revise_and_retry(self._incident(), max_attempts=3)

        assert seen_previous_attempts[0] is None
        assert seen_previous_attempts[1] is not None
        assert "errors" in seen_previous_attempts[1]
        assert draft.test_passed
        assert draft.attempt_number == 2
