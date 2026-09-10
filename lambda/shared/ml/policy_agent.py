"""
policy_agent.py — Layer 4: Autonomous Policy-Writing Agent
=============================================================
The propose -> test -> revise loop that earns the "agentic" label alongside
the orchestrator: draft a targeted IAM policy fix, test it in a sandbox,
feed any failures back into the next draft, and stop once the fix passes or
attempts run out. Nothing here ever touches real AWS — it produces a draft
for human approval.

LLM usage is behind a pluggable LLMClient interface, with two providers:
GroqLLMClient (OpenAI-compatible chat API, needs GROQ_API_KEY + the `groq`
package) and GeminiLLMClient (needs GEMINI_API_KEY + google-generativeai).
PolicyAgent auto-selects whichever is available (Groq preferred if both keys
are set — override with LLM_PROVIDER=gemini|groq), and falls back to
RuleBasedPolicyDrafter — a deterministic drafter that produces a minimal
least-privilege Deny patch — if neither is configured or a call fails. This
keeps the loop fully testable offline today, with a clear place to drop in a
real key later. Both keys can be dropped into a project-root .env file
(see .env.example) instead of exporting them by hand.

Sandbox strategy: PolicyEvaluator only for now (a ~150-line local Allow/Deny/
wildcard IAM evaluator). The doc's LocalStack-primary strategy is deferred —
LocalStack IAM enforcement is known to be unreliable, and this evaluator
covers the Allow/Deny/wildcard logic PolicyAgent's drafts actually use.

PolicyEvaluator scope (intentional, stated explicitly, matching the scope
decision made for lambda/shared/ml/blast_radius.py's IAM parser):
  Handled:      Effect (Allow/Deny) resolution, wildcard Action/Resource
                matching, explicit Deny overriding Allow, multiple statements.
  NOT handled:  Condition keys (aws:SourceIp, MFA, etc.), permission
                boundaries, resource-based policies, service control
                policies, session policies, cross-account evaluation.
"""

import os
import re
import json
import copy
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ml.env_loader import load_dotenv_once

logger = logging.getLogger(__name__)

GEMINI_MODEL_NAME = "gemini-2.0-flash"
GROQ_MODEL_NAME = "openai/gpt-oss-120b"
DEFAULT_MAX_ATTEMPTS = 3


def _build_policy_fix_prompt(incident: dict, blast_radius: dict, previous_attempt: dict = None) -> str:
    lines = [
        "You are a cloud security engineer drafting a minimal IAM policy fix.",
        "Respond with ONLY a JSON object with exactly these keys: "
        '"policy_json", "description", "rationale". No prose, no markdown fences.',
        "The fix must block the offending action/resource pair while preserving "
        "every other grant already present in the current policy.",
        f"Incident: {json.dumps(incident)}",
        f"Blast radius context: {json.dumps(blast_radius)}",
    ]
    if previous_attempt:
        lines.append(
            "Your previous attempt failed this test: "
            f"{json.dumps(previous_attempt)}. Fix the specific errors listed."
        )
    return "\n".join(lines)


def _parse_policy_fix_response(text: str) -> dict:
    cleaned = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    data = json.loads(cleaned)
    for key in ("policy_json", "description", "rationale"):
        if key not in data:
            raise ValueError(f"LLM response missing required key: {key}")
    return data


@dataclass
class PolicyDraft:
    policy_json: dict
    description: str
    rationale: str
    test_passed: bool = False
    attempt_number: int = 1
    errors: list = field(default_factory=list)


@dataclass
class TestResult:
    __test__ = False  # not a pytest test class despite the name

    passed: bool
    errors: list = field(default_factory=list)
    side_effects: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# PolicyEvaluator — scoped local IAM Allow/Deny/wildcard evaluator
# ---------------------------------------------------------------------------

class PolicyEvaluator:
    """Evaluates whether an IAM policy document permits a given action on a
    given resource, using AWS's own precedence rule: an explicit Deny always
    wins over any Allow, regardless of statement order.
    """

    def evaluate(self, policy_json: dict, action: str, resource: str) -> bool:
        statements = policy_json.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        denied = False
        allowed = False

        for stmt in statements:
            effect = stmt.get("Effect", "Allow")
            actions = self._as_list(stmt.get("Action", []))
            resources = self._as_list(stmt.get("Resource", []))

            if self._matches(action, actions) and self._matches(resource, resources):
                if effect == "Deny":
                    denied = True
                else:
                    allowed = True

        return allowed and not denied

    @staticmethod
    def _as_list(value) -> list:
        if isinstance(value, str):
            return [value]
        return list(value or [])

    @staticmethod
    def _matches(value: str, patterns: list) -> bool:
        for pattern in patterns:
            if pattern == "*" or pattern == value:
                return True
            if pattern.endswith("*") and value.startswith(pattern[:-1]):
                return True
        return False


# ---------------------------------------------------------------------------
# Pluggable LLM interface
# ---------------------------------------------------------------------------

class LLMClient(ABC):
    """Interface for anything that can draft an IAM policy fix from an incident."""

    @abstractmethod
    def draft_policy_fix(self, incident: dict, blast_radius: dict, previous_attempt: dict = None) -> dict:
        """Return {"policy_json": dict, "description": str, "rationale": str}."""
        raise NotImplementedError


class RuleBasedPolicyDrafter(LLMClient):
    """Deterministic fallback used when no LLM is configured or a call fails.

    Produces a minimal least-privilege patch: appends an explicit Deny for
    exactly the offending action/resource pair, leaving every other grant in
    the current policy untouched. This always gives the propose/test/revise
    loop something concrete to test, with zero external dependencies.
    """

    def draft_policy_fix(self, incident: dict, blast_radius: dict, previous_attempt: dict = None) -> dict:
        current_policy = copy.deepcopy(
            incident.get("current_policy") or {"Version": "2012-10-17", "Statement": []}
        )
        offending_action = incident["offending_action"]
        offending_resource = incident["offending_resource"]

        current_policy.setdefault("Statement", []).append({
            "Effect": "Deny",
            "Action": offending_action,
            "Resource": offending_resource,
        })

        return {
            "policy_json": current_policy,
            "description": f"Added an explicit Deny for {offending_action} on {offending_resource}.",
            "rationale": (
                "Rule-based least-privilege patch: blocks only the exact action/resource "
                "pair flagged by the incident, leaving all other grants unchanged. Used "
                "because no LLM was available or the LLM call failed."
            ),
        }


class GeminiLLMClient(LLMClient):
    """Drafts policy fixes with Gemini `gemini-2.0-flash` at temperature=0.

    Requires GEMINI_API_KEY (env var, .env file, or passed explicitly) and the
    google-generativeai package. is_available() lets callers check before
    attempting a call; draft_policy_fix() raises if unavailable so PolicyAgent
    can fall back cleanly.
    """

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

    def draft_policy_fix(self, incident: dict, blast_radius: dict, previous_attempt: dict = None) -> dict:
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured")

        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise RuntimeError("google-generativeai package is not installed") from exc

        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        prompt = _build_policy_fix_prompt(incident, blast_radius, previous_attempt)
        response = model.generate_content(prompt, generation_config={"temperature": 0})
        return _parse_policy_fix_response(response.text)

    # Kept as instance methods for backward compatibility with existing callers/tests.
    _build_prompt = staticmethod(_build_policy_fix_prompt)
    _parse_response = staticmethod(_parse_policy_fix_response)


class GroqLLMClient(LLMClient):
    """Drafts policy fixes via Groq's OpenAI-compatible chat API at temperature=0.

    Requires GROQ_API_KEY (env var, .env file, or passed explicitly) and the
    `groq` package. is_available() lets callers check before attempting a
    call; draft_policy_fix() raises if unavailable so PolicyAgent can fall
    back cleanly.
    """

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

    def draft_policy_fix(self, incident: dict, blast_radius: dict, previous_attempt: dict = None) -> dict:
        if not self.api_key:
            raise RuntimeError("GROQ_API_KEY is not configured")

        try:
            from groq import Groq
        except ImportError as exc:
            raise RuntimeError("groq package is not installed") from exc

        client = Groq(api_key=self.api_key)
        prompt = _build_policy_fix_prompt(incident, blast_radius, previous_attempt)
        response = client.chat.completions.create(
            model=self.model,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        return _parse_policy_fix_response(response.choices[0].message.content)


# ---------------------------------------------------------------------------
# PolicyAgent — the propose -> test -> revise loop
# ---------------------------------------------------------------------------

class PolicyAgent:
    """Layer 4: drafts a fix, tests it against PolicyEvaluator, and revises on
    failure up to max_attempts. Never applies anything — always returns a
    draft for a human to approve.
    """

    def __init__(self, llm_client: LLMClient = None, evaluator: PolicyEvaluator = None):
        self.llm_client = llm_client or self._default_client()
        self.evaluator = evaluator or PolicyEvaluator()

    @staticmethod
    def _default_client() -> LLMClient:
        load_dotenv_once()
        provider = os.environ.get("LLM_PROVIDER", "").lower()
        candidates = {"groq": GroqLLMClient, "gemini": GeminiLLMClient}
        order = [provider] if provider in candidates else ["groq", "gemini"]
        order += [name for name in candidates if name not in order]

        for name in order:
            client = candidates[name]()
            if client.is_available():
                logger.info("PolicyAgent using %s LLM client", name)
                return client

        logger.info("No LLM API key configured — PolicyAgent using RuleBasedPolicyDrafter")
        return RuleBasedPolicyDrafter()

    def draft_fix(self, incident: dict, blast_radius: dict = None, previous_attempt: dict = None) -> PolicyDraft:
        blast_radius = blast_radius or {}
        try:
            raw = self.llm_client.draft_policy_fix(incident, blast_radius, previous_attempt)
        except Exception as exc:
            logger.warning("LLM policy draft failed (%s); falling back to rule-based drafter", exc)
            raw = RuleBasedPolicyDrafter().draft_policy_fix(incident, blast_radius, previous_attempt)

        policy_json = self._coerce_policy_json(raw["policy_json"], incident, blast_radius, previous_attempt)

        return PolicyDraft(
            policy_json=policy_json,
            description=raw["description"],
            rationale=raw["rationale"],
        )

    def _coerce_policy_json(self, policy_json, incident: dict, blast_radius: dict, previous_attempt: dict) -> dict:
        """An LLM can return policy_json as a JSON-encoded *string* (double-
        encoding is a known, real LLM quirk) instead of the object it was
        asked for — found via direct testing (eval/layer4b_baseline_comparison_eval.py),
        not hypothetically: PolicyEvaluator.evaluate() calls policy_json.get(...)
        unconditionally, so a string here previously crashed with an unhandled
        AttributeError instead of the failure degrading to the normal
        test-fails-and-retries (or rule-based fallback) path. Un-wraps a
        JSON string once; if the result still isn't a dict, falls back to the
        deterministic rule-based drafter rather than let a malformed shape
        reach the sandbox evaluator at all."""
        if isinstance(policy_json, str):
            try:
                policy_json = json.loads(policy_json)
            except json.JSONDecodeError:
                pass
        if isinstance(policy_json, dict):
            return policy_json
        logger.warning("LLM returned a non-dict policy_json (%s); falling back to rule-based drafter",
                        type(policy_json).__name__)
        fallback = RuleBasedPolicyDrafter().draft_policy_fix(incident, blast_radius, previous_attempt)
        return fallback["policy_json"]

    def test_fix(self, draft: PolicyDraft, incident: dict) -> TestResult:
        """Sandbox test: the draft must block the offending action/resource pair
        and must NOT regress any action/resource pair the incident says must
        still be allowed."""
        errors = []

        still_allowed = self.evaluator.evaluate(
            draft.policy_json, incident["offending_action"], incident["offending_resource"]
        )
        if still_allowed:
            errors.append(
                f"Policy still allows {incident['offending_action']} on {incident['offending_resource']}"
            )

        for action, resource in incident.get("must_still_allow", []):
            if not self.evaluator.evaluate(draft.policy_json, action, resource):
                errors.append(f"Policy regressed: no longer allows required {action} on {resource}")

        return TestResult(passed=(len(errors) == 0), errors=errors)

    def revise_and_retry(self, incident: dict, blast_radius: dict = None,
                          max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> PolicyDraft:
        """Runs the full propose -> test -> revise cycle. Returns the last draft
        produced whether or not it ultimately passed — callers must check
        draft.test_passed before treating it as safe to propose to a human."""
        previous_attempt = None
        draft = None

        for attempt in range(1, max_attempts + 1):
            draft = self.draft_fix(incident, blast_radius, previous_attempt)
            draft.attempt_number = attempt

            result = self.test_fix(draft, incident)
            draft.test_passed = result.passed
            draft.errors = result.errors

            if result.passed:
                return draft

            previous_attempt = {"policy_json": draft.policy_json, "errors": result.errors}

        logger.warning(
            "PolicyAgent exhausted %d attempts for incident without a passing fix: %s",
            max_attempts, draft.errors if draft else "no draft produced",
        )
        return draft
