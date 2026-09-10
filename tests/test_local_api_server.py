"""
Unit Tests — Local API Server static file safety
==================================================
Covers the directory-traversal / path-prefix regression: FRONTEND_DIR was
checked with `file_path.startswith(FRONTEND_DIR)`, which has no separator
boundary — a sibling directory whose name merely starts with the same
string (e.g. "dist-evil" next to "dist") would pass the check. Fixed to
require an exact match or a path prefixed by FRONTEND_DIR + os.sep.

These tests exercise the actual server over a real socket rather than
re-implementing the check, so they catch a regression in the real code path.
"""

import os
import sys
import json
import shutil
import tempfile
import threading
import http.client

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

SCRIPT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPT_DIR)

import importlib.util

_spec = importlib.util.spec_from_file_location("local_api_server", os.path.join(SCRIPT_DIR, "local-api-server.py"))
local_api_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(local_api_server)


def _start_server():
    server = local_api_server.ThreadingHTTPServer(("127.0.0.1", 0), local_api_server.CSPMHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class TestStaticFileTraversal:
    @classmethod
    def setup_class(cls):
        # Use an isolated temp directory rather than the real FRONTEND_DIR —
        # that points at the actual `npm run build` output, which must not
        # be touched (let alone overwritten) by a test.
        cls._tmp_root = tempfile.mkdtemp(prefix="cspm-static-test-")
        cls._original_frontend_dir = local_api_server.FRONTEND_DIR
        cls.frontend_dir = os.path.join(cls._tmp_root, "dist")
        local_api_server.FRONTEND_DIR = cls.frontend_dir

        os.makedirs(cls.frontend_dir, exist_ok=True)
        with open(os.path.join(cls.frontend_dir, "index.html"), "w") as f:
            f.write("<html>ok</html>")

        # The specific case this regression enabled: a sibling directory whose
        # name merely starts with "dist" (FRONTEND_DIR's basename).
        cls.sibling_dir = cls.frontend_dir + "-evil"
        os.makedirs(cls.sibling_dir, exist_ok=True)
        with open(os.path.join(cls.sibling_dir, "secret.txt"), "w") as f:
            f.write("should never be served")

        cls.server, cls.port = _start_server()

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()
        local_api_server.FRONTEND_DIR = cls._original_frontend_dir
        shutil.rmtree(cls._tmp_root, ignore_errors=True)

    def _get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def test_legitimate_file_is_served(self):
        status, body = self._get("/index.html")
        assert status == 200
        assert b"ok" in body

    def test_parent_traversal_is_forbidden(self):
        status, _ = self._get("/../../../../../../etc/passwd")
        assert status in (403, 404)

    def test_sibling_directory_with_matching_prefix_is_not_served(self):
        """Regression: /../dist-evil/secret.txt used to pass the naive
        startswith(FRONTEND_DIR) check because "dist-evil" starts with "dist"."""
        status, body = self._get("/../" + os.path.basename(self.sibling_dir) + "/secret.txt")
        assert status == 403
        assert b"should never be served" not in body


class TestAiInsightsLimitValidation:
    """Regression: `limit=int(qs.get("limit", ["10"])[0])` had no try/except,
    so a non-numeric limit crashed into the generic exception handler and
    returned a 500 with the raw Python exception text leaked in the body,
    instead of a clean 400. Negative limits also had no lower bound, meaning
    Python slice semantics (list[:-1]) silently changed what was returned
    rather than erroring or being rejected."""

    @classmethod
    def setup_class(cls):
        cls.server, cls.port = _start_server()

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()

    def _get(self, path, timeout=60):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def test_non_numeric_limit_returns_clean_400(self):
        status, body = self._get("/ai/insights?limit=abc&source=demo")
        assert status == 400
        assert b"Traceback" not in body
        assert b"limit" in body

    def test_negative_limit_clamped_to_zero_not_python_slice_semantics(self):
        status, body = self._get("/ai/insights?limit=-1&source=demo")
        assert status == 200
        assert b'"results": []' in body


class TestLivePolicyFixContext:
    """_build_live_policy_fix_context() fetches a real IAM policy from
    LocalStack for an IAM Audit finding, so Policy Diff can draft a fix
    against real seeded events instead of only the 4 crafted demo scenarios.
    It must degrade to None (never raise) for anything it can't handle —
    a non-IAM-Audit finding, a malformed resource id, or (in an environment
    with no LocalStack running, e.g. CI) an unreachable IAM endpoint."""

    def test_non_iam_audit_type_returns_none_without_any_network_call(self):
        event = {"vulnerability_type": "S3 Public Access", "bucket_name": "some-bucket"}
        assert local_api_server.CSPMHandler._build_live_policy_fix_context(event) is None

    def test_malformed_resource_id_returns_none(self):
        event = {"vulnerability_type": "IAM Audit", "bucket_name": "not-a-user-or-role-prefix"}
        assert local_api_server.CSPMHandler._build_live_policy_fix_context(event) is None

    def test_nonexistent_identity_returns_none_not_an_exception(self):
        # Whether or not LocalStack is reachable in this environment, a
        # user that doesn't exist (or an unreachable endpoint) must resolve
        # to None, never propagate an exception up to the caller.
        event = {"vulnerability_type": "IAM Audit", "bucket_name": "User:definitely-does-not-exist-xyz"}
        assert local_api_server.CSPMHandler._build_live_policy_fix_context(event) is None


class TestAnalyzeEventEndpoint:
    """POST /ai/analyze-event runs the pipeline against exactly one event —
    these tests only exercise input validation, matching TestSimulateEndpoint's
    boundary (the real pipeline path needs a live LLM call, not exercised here)."""

    @classmethod
    def setup_class(cls):
        cls.server, cls.port = _start_server()

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()

    def _post(self, path, body_bytes, timeout=15):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        conn.request("POST", path, body=body_bytes, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def test_missing_bucket_name_returns_clean_400(self):
        status, body = self._post("/ai/analyze-event", b'{"vulnerability_type": "IAM Audit"}')
        assert status == 400
        assert b"Traceback" not in body

    def test_invalid_json_body_returns_clean_400(self):
        status, body = self._post("/ai/analyze-event", b"{not valid json")
        assert status == 400
        assert b"Traceback" not in body

    def test_non_object_body_returns_clean_400(self):
        status, body = self._post("/ai/analyze-event", b"[1, 2, 3]")
        assert status == 400
        assert b"Traceback" not in body


class TestDeployFixEndpoint:
    """POST /policies/deploy-fix applies a reviewed Layer 4 draft back to the
    real LocalStack identity it was drafted for. These tests only exercise
    input validation — the real apply path needs a live LocalStack IAM
    identity, not exercised here (see the manual live-fetch verification in
    GROWTH_PLAN.md's history for that path)."""

    @classmethod
    def setup_class(cls):
        cls.server, cls.port = _start_server()

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()

    def _post(self, path, body_bytes, timeout=15):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        conn.request("POST", path, body=body_bytes, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def test_missing_deploy_target_returns_clean_400(self):
        status, body = self._post("/policies/deploy-fix", b'{"policy_json": {"Version": "2012-10-17", "Statement": []}}')
        assert status == 400
        assert b"Traceback" not in body

    def test_invalid_kind_returns_clean_400(self):
        body_dict = {
            "deploy_target": {"kind": "group", "name": "x", "policy_name": "p"},
            "policy_json": {"Version": "2012-10-17", "Statement": []},
        }
        status, body = self._post("/policies/deploy-fix", json.dumps(body_dict).encode())
        assert status == 400
        assert b"Traceback" not in body

    def test_missing_policy_json_returns_clean_400(self):
        body_dict = {"deploy_target": {"kind": "user", "name": "x", "policy_name": "p"}}
        status, body = self._post("/policies/deploy-fix", json.dumps(body_dict).encode())
        assert status == 400
        assert b"Traceback" not in body

    def test_invalid_json_body_returns_clean_400(self):
        status, body = self._post("/policies/deploy-fix", b"{not valid json")
        assert status == 400
        assert b"Traceback" not in body


class TestSimulateEndpoint:
    """GROWTH_PLAN.md Phase 2: POST /simulate lets a targeted attack be
    triggered on demand instead of only replaying scripts/simulate-attacks.py's
    fixed demo sequence. These tests only exercise validation — they
    deliberately never let a real attack type reach the network (no
    LocalStack in the test environment), matching the boundary of what's
    testable without live infrastructure."""

    @classmethod
    def setup_class(cls):
        cls.server, cls.port = _start_server()

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()

    def _post(self, path, body_dict, timeout=10):
        import json as _json
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        payload = _json.dumps(body_dict).encode()
        conn.request("POST", path, body=payload, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def test_unknown_attack_type_returns_clean_400(self):
        status, body = self._post("/simulate", {"type": "bogus"})
        assert status == 400
        assert b"bogus" in body

    def test_missing_type_returns_clean_400(self):
        status, body = self._post("/simulate", {})
        assert status == 400

    def test_invalid_json_body_returns_clean_400(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/simulate", body=b"{not valid json", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        assert resp.status == 400
        assert b"Traceback" not in body


class TestSystemInfoEndpoint:
    """GET /system-info backs the Settings page — it must never leak a
    secret value (only booleans for whether one is configured), and must
    stay a cheap, always-200 read even when the AI engine or policy engine
    failed to import (those show up as availability flags, not errors)."""

    @classmethod
    def setup_class(cls):
        cls.server, cls.port = _start_server()

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()

    def _get(self, path, timeout=90):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def test_returns_200_with_expected_shape(self):
        import json as _json
        status, body = self._get("/system-info")
        assert status == 200
        data = _json.loads(body)
        for key in (
            "ai_engine_available", "github_configured", "discord_configured",
            "policies_total", "policies_enabled", "policies_pending_review",
            "simulate_attack_types", "simulate_available",
        ):
            assert key in data

    def test_never_echoes_a_secret_value(self):
        status, body = self._get("/system-info")
        assert status == 200
        # Only booleans are allowed to describe secret configuration —
        # the raw env var values must never appear in the response body.
        for secret in (os.environ.get("GITHUB_TOKEN"), os.environ.get("DISCORD_WEBHOOK_URL")):
            if secret:
                assert secret.encode() not in body
