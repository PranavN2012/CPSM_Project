"""
local-api-server.py — All-in-One CSPM Dashboard Server
======================================================
Serves the frontend (HTML/CSS/JS) AND proxies API calls to the Lambda
functions on LocalStack — all on a single port.

Also handles GitHub Issue creation via /create-issues endpoint.

One command, one URL, real data.

Usage:
    python scripts/local-api-server.py

Then open: http://localhost:3001
"""

import json
import os
import sys
import dataclasses
import mimetypes
import http.server
import socketserver
import urllib.parse
import threading
import boto3

# Windows consoles default to cp1252, which can't encode the emoji in the
# startup banner and log lines below — reconfigure to UTF-8 so the server
# doesn't crash on launch (same fix as scripts/simulate-attacks.py).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add shared modules to path
SCRIPT_DIR_P = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR_P = os.path.normpath(os.path.join(SCRIPT_DIR_P, ".."))
sys.path.insert(0, os.path.join(PROJECT_DIR_P, "lambda", "shared"))

try:
    from policy_engine import (
        load_policies, get_policy, update_policy,
        get_providers, policies_to_json, get_enabled_policies,
    )
    _HAS_POLICY_ENGINE = True
except ImportError:
    _HAS_POLICY_ENGINE = False

try:
    from policy_sync import sync_all, sync_from_github, sync_from_cis, sync_from_prowler
    _HAS_POLICY_SYNC = True
except ImportError:
    _HAS_POLICY_SYNC = False

try:
    from policy_generator import auto_generate_policy, get_pending_review_policies
    _HAS_POLICY_GENERATOR = True
except ImportError:
    _HAS_POLICY_GENERATOR = False

try:
    from providers import get_provider, list_providers
    _HAS_CLOUD_PROVIDERS = True
except ImportError:
    _HAS_CLOUD_PROVIDERS = False

LOCALSTACK_ENDPOINT = "http://localhost:4566"
API_LAMBDA_NAME = "cspm-s3-remediation-api"
IAM_AUDIT_LAMBDA_NAME = "cspm-s3-remediation-iam-audit"
SERVER_PORT = 3001
REGION = "us-east-1"

# ── AI Engine (Layers 1-5 + orchestrator) — lazy singleton ──────────────────
# These deps (scikit-learn, sentence-transformers, groq/google-generativeai)
# are host-side only (requirements-ai.txt), NOT bundled into the Lambda
# handlers — this is the intended integration surface for them. Imported
# lazily so a server without requirements-ai.txt installed still starts fine
# for everything else; only /ai/insights needs it, and SBERT's import alone
# takes several seconds, so it's not worth paying on every startup.
_orchestrator = None
_orchestrator_import_error = None


# Crafted attack scenarios that actually use the demo blast-radius graph's
# IAM principals (see lambda/shared/ml/data/blast_radius_seed.json), so
# Layer 3 produces real, meaningful output instead of the LOW default that
# live simulate-attacks.py events get (their bucket names don't match any
# graph node). Each scenario is a plausible incident: a specific identity
# doing something specific to a specific resource, at an hour and with
# characteristics Layer 1 was trained to flag.
DEMO_ATTACK_SCENARIOS = [
    {
        "event_id": "demo-1", "timestamp": "2026-06-12T03:14:00Z",
        "vulnerability_type": "IAM Audit", "severity": "CRITICAL",
        "bucket_name": "wildcard-admin-policy", "account_id": "999999999999",
        "region": "ap-southeast-1", "status": "IAM_OVERPERMISSIVE",
        "principal": "dev-intern-role",
        "nlp_summary": "A low-privilege intern role assumed a broad deployment role at 3 AM.",
        "policy_fix_context": {
            "current_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject",
                     "Resource": ["arn:aws:s3:::dev-user-uploads/*", "arn:aws:s3:::staging-logs-2026/*"]},
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
                ],
            },
            "offending_action": "sts:AssumeRole",
            "offending_resource": "arn:aws:iam::999999999999:role/ci-deploy-role",
            "must_still_allow": [["s3:GetObject", "arn:aws:s3:::dev-user-uploads/notes.txt"]],
        },
    },
    {
        "event_id": "demo-2", "timestamp": "2026-06-12T02:47:00Z",
        "vulnerability_type": "S3 Public Access", "severity": "CRITICAL",
        "bucket_name": "prod-data-lake-raw", "account_id": "123456789012",
        "region": "eu-west-1", "status": "IAM_OVERPERMISSIVE",
        "principal": "ci-deploy-role",
        "nlp_summary": "The CI/CD deployment role directly administers production data buckets.",
        # Supplies what Layer 4 needs to actually draft a fix — without this,
        # the orchestrator can only escalate_to_human even for a CRITICAL
        # finding, since attempt_auto_fix requires something concrete to fix.
        "policy_fix_context": {
            "current_policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
            },
            "offending_action": "s3:PutBucketPolicy",
            "offending_resource": "arn:aws:s3:::prod-data-lake-raw",
            "must_still_allow": [["s3:GetObject", "arn:aws:s3:::prod-data-lake-raw"]],
        },
    },
    {
        "event_id": "demo-3", "timestamp": "2026-06-13T04:02:00Z",
        "vulnerability_type": "DynamoDB Unencrypted", "severity": "HIGH",
        "bucket_name": "session-tokens-table", "account_id": "123456789012",
        "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
        "principal": "backup-service-role",
        "nlp_summary": "The backup service role read a table holding session tokens outside its normal backup window.",
        "policy_fix_context": {
            "current_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:*",
                     "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/session-tokens-table"},
                ],
            },
            "offending_action": "dynamodb:UpdateTable",
            "offending_resource": "arn:aws:dynamodb:us-east-1:123456789012:table/session-tokens-table",
            "must_still_allow": [
                ["dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:123456789012:table/session-tokens-table"],
                ["dynamodb:Scan", "arn:aws:dynamodb:us-east-1:123456789012:table/session-tokens-table"],
            ],
        },
    },
    {
        "event_id": "demo-4", "timestamp": "2026-06-13T01:30:00Z",
        "vulnerability_type": "S3 Encryption", "severity": "MEDIUM",
        "bucket_name": "ml-training-datasets", "account_id": "123456789012",
        "region": "us-west-2", "status": "IAM_OVERPERMISSIVE",
        "principal": "analyst-user",
        "nlp_summary": "An analyst account accessed ML training data, then assumed the backup service role.",
        "policy_fix_context": {
            "current_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*",
                     "Resource": ["arn:aws:s3:::ml-training-datasets", "arn:aws:s3:::ml-training-datasets/*"]},
                ],
            },
            "offending_action": "s3:PutEncryptionConfiguration",
            "offending_resource": "arn:aws:s3:::ml-training-datasets",
            "must_still_allow": [["s3:GetObject", "arn:aws:s3:::ml-training-datasets/training-set-v3.csv"]],
        },
    },
]


def _get_orchestrator():
    global _orchestrator, _orchestrator_import_error
    if _orchestrator is not None or _orchestrator_import_error is not None:
        return _orchestrator
    try:
        from ml.orchestrator import ThreatOrchestrator
        _orchestrator = ThreatOrchestrator()
    except Exception as exc:  # ImportError (deps missing) or init failure
        _orchestrator_import_error = str(exc)
    return _orchestrator


# ── Attack Simulator — lazy import ───────────────────────────────────────
# simulate-attacks.py has a hyphen in its filename (not a valid module
# name), so it's loaded via importlib.util instead of a plain import —
# same technique used by tests/test_local_api_server.py for this same file.
_attack_simulator = None
_attack_simulator_import_error = None


def _get_attack_simulator():
    global _attack_simulator, _attack_simulator_import_error
    if _attack_simulator is not None or _attack_simulator_import_error is not None:
        return _attack_simulator
    try:
        import importlib.util
        sim_path = os.path.join(SCRIPT_DIR_P, "simulate-attacks.py")
        spec = importlib.util.spec_from_file_location("simulate_attacks", sim_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _attack_simulator = module
    except Exception as exc:
        _attack_simulator_import_error = str(exc)
    return _attack_simulator

# GitHub config
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = "PranavN2012/CPSM_Project"

# Resolve the frontend build output relative to this script.
# frontend/ is now a Vite+React app — `npm run build` (inside frontend/)
# produces frontend/dist/, which is what gets served here. During
# development, run `npm run dev` in frontend/ instead (Vite's dev server
# proxies API calls back to this same server — see frontend/vite.config.js).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "frontend", "dist"))

lambda_client = boto3.client(
    "lambda",
    endpoint_url=LOCALSTACK_ENDPOINT,
    region_name=REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Plain HTTPServer is single-threaded — one slow request (e.g. a boto3
    Lambda invoke against LocalStack) blocks every other request, including
    serving the frontend's own JS/CSS. A browser page load fires several
    requests at once, so this isn't optional for real usage."""
    daemon_threads = True


class CSPMHandler(http.server.BaseHTTPRequestHandler):
    """
    Combined handler:
      - GET /events, /stats  →  proxy to API Lambda on LocalStack
      - POST /create-issues  →  create GitHub Issues from recent events
      - GET / or /index.html →  serve frontend/index.html
      - GET /*.css, /*.js    →  serve static frontend files
    """

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # ── API routes → invoke Lambda ──
        if path in ("/events", "/stats"):
            self._handle_api(path)
            return

        # ── Policy Engine routes ──
        if path == "/policies":
            self._handle_get_policies()
            return
        if path == "/providers":
            self._handle_get_providers()
            return

        # ── Compliance (computed locally) ──
        if path == "/compliance":
            self._handle_compliance()
            return

        # ── Trends (computed locally) ──
        if path == "/trends":
            self._handle_trends()
            return

        # ── PDF Report download ──
        if path == "/report":
            self._handle_report()
            return

        # ── AI Engine (Layers 1-5 + orchestrator) ──
        if path == "/ai/insights":
            self._handle_ai_insights(parsed)
            return

        # ── System status (for the Settings page) ──
        if path == "/system-info":
            self._handle_system_info()
            return

        # ── Multi-Cloud Scan ──
        if path.startswith("/scan/"):
            provider_slug = path.split("/scan/")[1]
            self._handle_scan(provider_slug)
            return

        # ── Static frontend files ──
        self._serve_static(path)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/create-issues":
            self._handle_create_issues()
            return

        if path == "/ai/analyze-event":
            self._handle_analyze_event()
            return

        # Policy sync endpoints
        if path == "/policies/sync":
            self._handle_sync_all()
            return
        if path == "/policies/sync/github":
            self._handle_sync_github()
            return
        if path == "/policies/sync/cis":
            self._handle_sync_cis()
            return
        if path == "/policies/sync/prowler":
            self._handle_sync_prowler()
            return
        if path == "/policies/auto-generate":
            self._handle_auto_generate()
            return
        if path == "/policies/deploy-fix":
            self._handle_deploy_fix()
            return

        if path == "/simulate":
            self._handle_simulate()
            return

        self._respond_json(404, {"error": f"Not found: {path}"})

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        # PUT /policies/<policy_id>
        if path.startswith("/policies/"):
            policy_id = path[len("/policies/"):]
            self._handle_update_policy(policy_id)
            return

        self._respond_json(404, {"error": f"Not found: {path}"})

    def do_OPTIONS(self):
        """CORS preflight."""
        self.send_response(200)
        self._add_cors_headers()
        self.end_headers()

    # ── API Proxy ───────────────────────────────────────────────────────

    def _handle_api(self, path):
        api_event = {
            "version": "2.0",
            "rawPath": path,
            "requestContext": {
                "http": {"method": "GET", "path": path},
            },
        }

        try:
            resp = lambda_client.invoke(
                FunctionName=API_LAMBDA_NAME,
                Payload=json.dumps(api_event),
            )
            payload = json.loads(resp["Payload"].read())
            status = payload.get("statusCode", 500)
            body = json.loads(payload.get("body", "{}"))
            self._respond_json(status, body)

        except Exception as exc:
            print(f"  [ERROR] Lambda invocation failed: {exc}")
            self._respond_json(500, {"error": str(exc)})

    # ── Compliance (local computation) ──────────────────────────────────

    def _get_events_from_lambda(self):
        """Helper: Fetch events from API Lambda."""
        resp = lambda_client.invoke(
            FunctionName=API_LAMBDA_NAME,
            Payload=json.dumps({
                "version": "2.0", "rawPath": "/events",
                "requestContext": {"http": {"method": "GET", "path": "/events"}},
            }),
        )
        payload = json.loads(resp["Payload"].read())
        return json.loads(payload.get("body", "{}")).get("events", [])

    # ── AI Engine (Layers 1-5 + orchestrator) ────────────────────────────

    def _map_event_for_ai(self, event):
        """CSPM event schema already matches what Layer 1/2 expect
        (timestamp, vulnerability_type, severity, bucket_name, account_id,
        region) — the only addition needed is a blast-radius entry point.

        Whether the resource name matches an IAM identity is now resolved
        live against the orchestrator's actual InfraGraph (node type
        IAMRole/IAMUser) instead of a hand-maintained set duplicating the
        seed graph's node IDs — expanding the graph (new principals, new
        edges) no longer requires touching this file too. `bucket_name` is
        passed through unchanged either way: even when it isn't an identity,
        ThreatOrchestrator._safe_blast_radius() now also checks it against
        the graph directly and falls back to a resource-exposure severity
        check for known non-identity nodes (e.g. a live S3 Public Access
        finding on a bucket that happens to match a real graph node — see
        scripts/simulate-attacks.py's BUCKET_NAMES)."""
        mapped = dict(event)
        resource = str(event.get("bucket_name", ""))
        orchestrator = _get_orchestrator()
        if orchestrator is not None:
            node = orchestrator.infra_graph.nodes.get(resource)
            if node and node["type"] in ("IAMRole", "IAMUser"):
                mapped["principal"] = resource
        if "policy_fix_context" not in mapped:
            live_context = self._build_live_policy_fix_context(event)
            if live_context is not None:
                mapped["policy_fix_context"] = live_context
        return mapped

    @staticmethod
    def _build_live_policy_fix_context(event):
        """For a real IAM Audit finding, fetch the ACTUAL current IAM policy
        from LocalStack so Layer 4 can draft a fix against real live state —
        the same mechanism the 4 crafted DEMO_ATTACK_SCENARIOS use, just
        sourced from a real boto3 call instead of a hand-written fixture.

        Only IAM Audit findings produce a real IAM *policy* to diff: S3
        Public Access/Encryption, Security Group, and DynamoDB findings are
        remediated by flipping a resource config flag directly (see
        lambda/remediation/lambda_function.py) — there is no IAM policy
        document behind those, so this intentionally returns None for them
        rather than fabricating one. Also returns None if the identity or
        its inline policy no longer exists (e.g. already cleaned up) —
        callers must treat that as "no draft possible for this incident
        right now", never silently substitute different data."""
        if event.get("vulnerability_type") != "IAM Audit":
            return None
        resource = str(event.get("bucket_name", ""))
        if resource.startswith("User:"):
            kind, name = "user", resource[len("User:"):]
        elif resource.startswith("Role:"):
            kind, name = "role", resource[len("Role:"):]
        else:
            return None

        iam_client = boto3.client(
            "iam", endpoint_url=LOCALSTACK_ENDPOINT, region_name=REGION,
            aws_access_key_id="test", aws_secret_access_key="test",
        )
        key = "UserName" if kind == "user" else "RoleName"
        list_fn = iam_client.list_user_policies if kind == "user" else iam_client.list_role_policies
        get_fn = iam_client.get_user_policy if kind == "user" else iam_client.get_role_policy
        try:
            policy_names = list_fn(**{key: name}).get("PolicyNames", [])
            if not policy_names:
                return None
            policy_doc = get_fn(**{key: name, "PolicyName": policy_names[0]})["PolicyDocument"]
        except Exception as exc:
            print(f"  [INFO] Could not fetch live policy for {resource}: {exc}")
            return None

        offending_action, offending_resource = "*", "*"
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            actions = actions if isinstance(actions, list) else [actions]
            if "*" in actions:
                res = stmt.get("Resource", "*")
                offending_action = "*"
                offending_resource = res if isinstance(res, str) else (res[0] if res else "*")
                break
            if actions:
                offending_action = actions[0]
                res = stmt.get("Resource", "*")
                offending_resource = res if isinstance(res, str) else (res[0] if res else "*")

        return {
            "current_policy": policy_doc,
            "offending_action": offending_action,
            "offending_resource": offending_resource,
            "must_still_allow": [],
            # Not read by PolicyAgent/PolicyEvaluator (they only use the 4
            # keys above) — carried through to the frontend so a sandbox-
            # verified draft can actually be deployed back to this exact
            # identity/policy via POST /policies/deploy-fix, instead of the
            # review page being read-only for real incidents.
            "deploy_target": {"kind": kind, "name": name, "policy_name": policy_names[0]},
        }

    def _handle_ai_insights(self, parsed):
        """GET /ai/insights?limit=N&source=live|demo — runs events through
        the full AI pipeline (Layers 1-5 + orchestrator) and returns each
        event's anomaly score, ATT&CK classification, blast radius, priority
        tier, and the orchestrator's decision + rationale.

        source=live (default): the most recent N real events from DynamoDB.
        Their bucket names don't match any node in the demo blast-radius
        graph, so Layer 3 honestly reports LOW for all of them.

        source=demo: DEMO_ATTACK_SCENARIOS — crafted incidents that use the
        actual IAM principals in lambda/shared/ml/data/blast_radius_seed.json
        (dev-intern-role, ci-deploy-role, etc.), so Layer 3 produces real,
        varied blast-radius output. Clearly labeled as scenarios, not live
        telemetry — this is a demo of what the pipeline does with an entry
        point it can actually resolve, not fabricated results."""
        orchestrator = _get_orchestrator()
        if orchestrator is None:
            self._respond_json(501, {
                "error": "AI engine not available",
                "detail": _orchestrator_import_error or "unknown import failure",
                "hint": "pip install -r requirements-ai.txt",
            })
            return

        try:
            qs = urllib.parse.parse_qs(parsed.query)
            limit_raw = qs.get("limit", ["10"])[0]
            try:
                # Clamp both ends: negative would silently mean "all but the
                # last N" via Python slicing (confusing, not an error), and
                # the upper cap keeps a single request from running the live
                # SBERT + LLM pipeline over an unbounded number of events.
                limit = max(0, min(int(limit_raw), 25))
            except (TypeError, ValueError):
                self._respond_json(400, {"error": f"limit must be an integer, got {limit_raw!r}"})
                return
            source = qs.get("source", ["live"])[0]

            if source == "demo":
                raw_events = DEMO_ATTACK_SCENARIOS[:limit]
            else:
                raw_events = self._get_events_from_lambda()[:limit]

            results = []
            for event in raw_events:
                mapped = self._map_event_for_ai(event)
                result = orchestrator.process_event(mapped)
                results.append(self._serialize_orchestrator_result(result))

            self._respond_json(200, {
                "results": results,
                "source": source,
                "reasoner": orchestrator.reasoner.__class__.__name__,
                "llm_client": orchestrator.policy_agent.llm_client.__class__.__name__,
            })
        except Exception as exc:
            print(f"  [ERROR] AI insights failed: {exc}")
            self._respond_json(500, {"error": str(exc)})

    def _handle_analyze_event(self):
        """POST /ai/analyze-event — run the full pipeline against exactly
        ONE event supplied in the request body, instead of "the most recent
        N" or a fixed demo list. This is what the Policy Diff page uses so
        it always analyzes the specific incident the user actually clicked
        (from the Dashboard's Priority Queue or Events table), never a
        substituted demo scenario.

        For a real IAM Audit finding, _map_event_for_ai attaches a live
        policy_fix_context fetched straight from LocalStack IAM — so the
        resulting draft is verified against the identity's actual current
        policy, not a hand-written fixture. Other real finding types (S3,
        Security Group, DynamoDB) have no IAM policy behind them — the
        orchestrator will honestly decide there's nothing to draft rather
        than one being fabricated for the occasion."""
        orchestrator = _get_orchestrator()
        if orchestrator is None:
            self._respond_json(501, {
                "error": "AI engine not available",
                "detail": _orchestrator_import_error or "unknown import failure",
                "hint": "pip install -r requirements-ai.txt",
            })
            return

        content_length = int(self.headers.get("Content-Length", 0))
        try:
            event = json.loads(self.rfile.read(content_length)) if content_length else {}
        except json.JSONDecodeError as exc:
            self._respond_json(400, {"error": f"Invalid JSON body: {exc}"})
            return
        if not isinstance(event, dict) or not event.get("bucket_name"):
            self._respond_json(400, {"error": "Body must be an event object with at least a bucket_name."})
            return

        try:
            mapped = self._map_event_for_ai(event)
            result = orchestrator.process_event(mapped)
            self._respond_json(200, {
                "result": self._serialize_orchestrator_result(result),
                "reasoner": orchestrator.reasoner.__class__.__name__,
                "llm_client": orchestrator.policy_agent.llm_client.__class__.__name__,
            })
        except Exception as exc:
            print(f"  [ERROR] Single-event analysis failed: {exc}")
            self._respond_json(500, {"error": str(exc)})

    def _handle_deploy_fix(self):
        """POST /policies/deploy-fix — apply a sandbox-verified Layer 4 draft
        back to the real (LocalStack) identity it was drafted for.

        Body: {"deploy_target": {"kind": "user"|"role", "name": ..., "policy_name": ...},
               "policy_json": {...}}
        Both come straight from a prior /ai/analyze-event response
        (event.policy_fix_context.deploy_target and policy_draft.policy_json)
        — this endpoint doesn't re-derive or re-verify them, it only applies
        exactly what the human reviewed on the Policy Diff page. It does NOT
        re-run PolicyEvaluator; that already happened before this draft was
        shown as safe to deploy. Never touches real AWS — LOCALSTACK_ENDPOINT
        is the only endpoint boto3 is pointed at here, same as every other
        write in this file.

        After applying, re-runs the IAM audit scan so the dashboard reflects
        the fix immediately rather than waiting for the next scheduled scan."""
        content_length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(content_length)) if content_length else {}
        except json.JSONDecodeError as exc:
            self._respond_json(400, {"error": f"Invalid JSON body: {exc}"})
            return

        target = body.get("deploy_target") or {}
        policy_json = body.get("policy_json")
        kind, name, policy_name = target.get("kind"), target.get("name"), target.get("policy_name")
        if kind not in ("user", "role") or not name or not policy_name or not isinstance(policy_json, dict):
            self._respond_json(400, {
                "error": "Body must include deploy_target: {kind: 'user'|'role', name, policy_name} and a policy_json object.",
            })
            return

        iam_client = boto3.client(
            "iam", endpoint_url=LOCALSTACK_ENDPOINT, region_name=REGION,
            aws_access_key_id="test", aws_secret_access_key="test",
        )
        key = "UserName" if kind == "user" else "RoleName"
        put_fn = iam_client.put_user_policy if kind == "user" else iam_client.put_role_policy
        try:
            put_fn(**{key: name, "PolicyName": policy_name, "PolicyDocument": json.dumps(policy_json)})
        except Exception as exc:
            print(f"  [ERROR] Deploy fix failed for {kind}:{name}: {exc}")
            self._respond_json(500, {"error": f"Failed to apply policy to LocalStack: {exc}"})
            return

        identity_resource = f"{'User' if kind == 'user' else 'Role'}:{name}"
        remaining_findings = None
        try:
            resp = lambda_client.invoke(FunctionName=IAM_AUDIT_LAMBDA_NAME, Payload=json.dumps({
                "account": "123456789012", "region": REGION,
            }))
            payload = json.loads(resp["Payload"].read())
            rescan = json.loads(payload.get("body", "{}"))
            remaining_findings = [
                f for f in rescan.get("findings", [])
                if f.get("resource") == identity_resource
            ]
        except Exception as exc:
            print(f"  [WARN] Deployed but re-scan failed: {exc}")

        # Without this, a genuinely fixed identity's compliance score never
        # recovers: the IAM audit scanner only ever LOGS an event when it
        # FINDS a problem — a clean re-scan logs nothing, so the original
        # IAM_OVERPERMISSIVE event (which compliance.py permanently counts
        # as FAIL) just sits there forever even after a real, verified fix.
        # If the re-scan confirms zero findings for this identity, flip its
        # prior flagged events to COMPLIANT so the compliance score reflects
        # the fix that was actually just applied.
        resolved_count = 0
        if remaining_findings == []:
            try:
                dynamodb_resource = boto3.resource(
                    "dynamodb", endpoint_url=LOCALSTACK_ENDPOINT, region_name=REGION,
                    aws_access_key_id="test", aws_secret_access_key="test",
                )
                table = dynamodb_resource.Table("cspm-remediation-events")
                for item in table.scan().get("Items", []):
                    if (item.get("bucket_name") == identity_resource
                            and item.get("vulnerability_type") == "IAM Audit"
                            and item.get("status") == "IAM_OVERPERMISSIVE"):
                        item["status"] = "COMPLIANT"
                        item["severity"] = "LOW"
                        table.put_item(Item=item)
                        resolved_count += 1
            except Exception as exc:
                print(f"  [WARN] Deployed and verified clean, but couldn't update prior findings' compliance status: {exc}")

        self._respond_json(200, {
            "deployed": True,
            "identity": identity_resource,
            "policy_name": policy_name,
            "rescanned": remaining_findings is not None,
            "remaining_findings_for_identity": remaining_findings,
            "prior_findings_marked_compliant": resolved_count,
        })

    @staticmethod
    def _serialize_orchestrator_result(result):
        data = dataclasses.asdict(result)
        # `event` is the raw/mapped CSPM event dict — already JSON-safe.
        return data

    def _handle_system_info(self):
        """GET /system-info — read-only snapshot of what's actually
        configured/running, for the Settings page. No secrets are returned,
        only booleans and the operational constants that shape the pipeline's
        behavior (thresholds, which LLM client is active, how many policies
        are pending human review)."""
        orchestrator = _get_orchestrator()
        info = {
            "ai_engine_available": orchestrator is not None,
            "ai_engine_error": None if orchestrator is not None else _orchestrator_import_error,
            "github_configured": bool(GITHUB_TOKEN),
            "discord_configured": bool(os.environ.get("DISCORD_WEBHOOK_URL")),
            "github_repo": GITHUB_REPO,
        }

        if orchestrator is not None:
            info["reasoner"] = orchestrator.reasoner.__class__.__name__
            info["llm_client"] = orchestrator.policy_agent.llm_client.__class__.__name__
            info["anomaly_threshold"] = orchestrator.anomaly_threshold
            try:
                info["attack_classifier_threshold"] = orchestrator.attack_classifier.threshold
                info["attack_classifier_calibrated"] = orchestrator.attack_classifier.is_threshold_calibrated
            except Exception as exc:
                info["attack_classifier_threshold"] = None
                info["attack_classifier_calibrated"] = None
                info["attack_classifier_error"] = str(exc)

        if _HAS_POLICY_ENGINE:
            policies_dir = os.path.join(PROJECT_DIR_P, "policies")
            policies = load_policies(policies_dir=policies_dir, force_reload=True)
            info["policies_total"] = len(policies)
            info["policies_enabled"] = len([p for p in policies if p.get("enabled", True)])
            info["policies_pending_review"] = len([p for p in policies if p.get("needs_review") or p.get("auto_generated")])
        else:
            info["policies_total"] = info["policies_enabled"] = info["policies_pending_review"] = None

        simulator = _get_attack_simulator()
        info["simulate_attack_types"] = list(simulator.TARGETED_ATTACK_TYPES) if simulator is not None else []
        info["simulate_available"] = simulator is not None

        self._respond_json(200, info)

    def _handle_compliance(self):
        """Compute compliance framework scores locally."""
        try:
            import sys as _sys
            _sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "lambda", "shared"))
            from compliance import get_compliance_summary

            events = self._get_events_from_lambda()
            summary = get_compliance_summary(events)
            self._respond_json(200, summary)
        except Exception as exc:
            print(f"  [ERROR] Compliance computation failed: {exc}")
            import traceback; traceback.print_exc()
            self._respond_json(500, {"error": str(exc)})

    def _handle_trends(self):
        """Compute daily compliance scores locally."""
        try:
            events = self._get_events_from_lambda()

            daily = {}
            for item in events:
                date = item.get("timestamp", "")[:10]
                if not date:
                    continue
                if date not in daily:
                    daily[date] = {"total": 0, "remediated": 0}
                daily[date]["total"] += 1
                if item.get("status") in ("REMEDIATED", "ENCRYPTION_REMEDIATED", "COMPLIANT"):
                    daily[date]["remediated"] += 1

            trend_data = []
            for date in sorted(daily.keys()):
                d = daily[date]
                score = round(d["remediated"] / d["total"] * 100, 1) if d["total"] > 0 else 0
                trend_data.append({"date": date, "score": score, "events": d["total"]})

            self._respond_json(200, {"trends": trend_data})
        except Exception as exc:
            print(f"  [ERROR] Trends computation failed: {exc}")
            self._respond_json(500, {"error": str(exc)})

    # ── GitHub Issue Creation ────────────────────────────────────────────

    def _handle_create_issues(self):
        """Fetch recent events from DynamoDB and create GitHub Issues."""
        import requests as req

        if not GITHUB_TOKEN or not GITHUB_REPO:
            self._respond_json(400, {"error": "GitHub not configured"})
            return

        # Read POST body if any (optional filter)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            body = json.loads(self.rfile.read(content_length))
        else:
            body = {}

        # Get events from DynamoDB via Lambda
        try:
            resp = lambda_client.invoke(
                FunctionName=API_LAMBDA_NAME,
                Payload=json.dumps({
                    "version": "2.0",
                    "rawPath": "/events",
                    "requestContext": {"http": {"method": "GET", "path": "/events"}},
                }),
            )
            payload = json.loads(resp["Payload"].read())
            events_body = json.loads(payload.get("body", "{}"))
            events = events_body.get("events", [])
        except Exception as exc:
            self._respond_json(500, {"error": f"Failed to fetch events: {exc}"})
            return

        # Filter to non-compliant events only
        actionable = [e for e in events if e.get("status") not in ("COMPLIANT",)]

        # Limit to most recent 5 actionable events
        limit = body.get("limit", 5)
        to_create = actionable[:limit]

        results = []
        created = 0
        failed = 0

        for event in to_create:
            vuln_type = event.get("vulnerability_type", "S3 Public Access")
            resource = event.get("bucket_name", "unknown")
            status = event.get("status", "unknown")
            severity = event.get("severity", "HIGH")
            region = event.get("region", "unknown")
            account = event.get("account_id", "unknown")

            icon_map = {"S3 Public Access": "🛡️", "S3 Encryption": "🔐", "IAM Audit": "👤"}
            sev_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

            icon = icon_map.get(vuln_type, "🔍")
            sev_icon = sev_map.get(severity, "⚪")

            title = f"{icon} {vuln_type}: {resource} [{status}]"
            issue_body = (
                f"## {sev_icon} {vuln_type} — Severity: {severity}\n\n"
                f"| Field | Value |\n"
                f"|-------|-------|\n"
                f"| **Resource** | `{resource}` |\n"
                f"| **Account** | `{account}` |\n"
                f"| **Region** | `{region}` |\n"
                f"| **Status** | **{status}** |\n"
                f"| **Severity** | {sev_icon} {severity} |\n\n"
                f"---\n*Auto-generated by Serverless CSPM*"
            )

            labels = ["cspm", "security"]
            if "REMEDIATED" in status:
                labels.append("auto-remediated")
            else:
                labels.append("needs-attention")

            try:
                r = req.post(
                    f"https://api.github.com/repos/{GITHUB_REPO}/issues",
                    headers={
                        "Authorization": f"token {GITHUB_TOKEN}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                    json={"title": title, "body": issue_body, "labels": labels},
                    timeout=10,
                )
                if r.status_code in (200, 201):
                    url = r.json().get("html_url", "")
                    results.append({"resource": resource, "status": "created", "url": url})
                    created += 1
                    print(f"  [GitHub] Created issue: {url}")
                else:
                    results.append({"resource": resource, "status": "failed", "error": r.text[:100]})
                    failed += 1
            except req.exceptions.Timeout:
                results.append({"resource": resource, "status": "timeout"})
                failed += 1
                print(f"  [GitHub] Timeout creating issue for {resource}")
            except Exception as exc:
                results.append({"resource": resource, "status": "error", "error": str(exc)[:100]})
                failed += 1

        self._respond_json(200, {
            "created": created,
            "failed": failed,
            "total": len(to_create),
            "issues": results,
        })

    # ── PDF Report ──────────────────────────────────────────────────────

    def _handle_report(self):
        """Generate and serve a PDF compliance report."""
        try:
            # Get events and stats from Lambda
            events_resp = lambda_client.invoke(
                FunctionName=API_LAMBDA_NAME,
                Payload=json.dumps({
                    "version": "2.0", "rawPath": "/events",
                    "requestContext": {"http": {"method": "GET", "path": "/events"}},
                }),
            )
            events_payload = json.loads(events_resp["Payload"].read())
            events = json.loads(events_payload.get("body", "{}")).get("events", [])

            stats_resp = lambda_client.invoke(
                FunctionName=API_LAMBDA_NAME,
                Payload=json.dumps({
                    "version": "2.0", "rawPath": "/stats",
                    "requestContext": {"http": {"method": "GET", "path": "/stats"}},
                }),
            )
            stats_payload = json.loads(stats_resp["Payload"].read())
            stats = json.loads(stats_payload.get("body", "{}"))

            # Generate PDF
            from report_generator import generate_report
            pdf_bytes = generate_report(events, stats)

            # Serve PDF
            self.send_response(200)
            self._add_cors_headers()
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", "attachment; filename=CSPM_Compliance_Report.pdf")
            self.send_header("Content-Length", str(len(pdf_bytes)))
            self.end_headers()
            self.wfile.write(pdf_bytes)
            print(f"  [Report] Generated PDF ({len(pdf_bytes)} bytes)")

        except Exception as exc:
            print(f"  [ERROR] Report generation failed: {exc}")
            import traceback
            traceback.print_exc()
            self._respond_json(500, {"error": str(exc)})

    # ── Static File Server ──────────────────────────────────────────────

    def _serve_static(self, path):
        # Map / to the Vite build's index.html
        if path == "/":
            path = "/index.html"

        # Security: prevent directory traversal
        safe_path = os.path.normpath(path.lstrip("/"))
        file_path = os.path.join(FRONTEND_DIR, safe_path)
        file_path = os.path.normpath(file_path)

        if not (file_path == FRONTEND_DIR or file_path.startswith(FRONTEND_DIR + os.sep)):
            self._respond_json(403, {"error": "Forbidden"})
            return

        if not os.path.isdir(FRONTEND_DIR):
            self._respond_json(
                404,
                {"error": "frontend/dist not found — run `npm install && npm run build` inside frontend/ first."},
            )
            return

        if not os.path.isfile(file_path):
            self._respond_json(404, {"error": f"Not found: {path}"})
            return

        content_type, _ = mimetypes.guess_type(file_path)
        content_type = content_type or "application/octet-stream"

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)

        except Exception as exc:
            self._respond_json(500, {"error": str(exc)})

    # ── Policy Engine API ────────────────────────────────────────────────

    def _handle_get_policies(self):
        """GET /policies — return all policies."""
        if not _HAS_POLICY_ENGINE:
            self._respond_json(501, {"error": "Policy engine not available"})
            return
        policies_dir = os.path.join(PROJECT_DIR_P, "policies")
        policies = load_policies(policies_dir=policies_dir, force_reload=True)
        self._respond_json(200, {
            "policies": [{k: v for k, v in p.items() if not k.startswith("_")} for p in policies],
            "total": len(policies),
            "enabled": len([p for p in policies if p.get("enabled", True)]),
        })

    def _handle_get_providers(self):
        """GET /providers — return registered cloud providers."""
        if not _HAS_POLICY_ENGINE:
            self._respond_json(501, {"error": "Policy engine not available"})
            return
        # Ensure policies are loaded first
        policies_dir = os.path.join(PROJECT_DIR_P, "policies")
        load_policies(policies_dir=policies_dir, force_reload=True)
        providers = get_providers()
        self._respond_json(200, {"providers": providers})

    def _handle_update_policy(self, policy_id):
        """PUT /policies/<id> — toggle or edit a policy."""
        if not _HAS_POLICY_ENGINE:
            self._respond_json(501, {"error": "Policy engine not available"})
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length)) if content_length else {}

        # Ensure policies are loaded
        policies_dir = os.path.join(PROJECT_DIR_P, "policies")
        load_policies(policies_dir=policies_dir, force_reload=True)

        updated = update_policy(policy_id, body)
        if updated:
            clean = {k: v for k, v in updated.items() if not k.startswith("_")}
            self._respond_json(200, {"policy": clean, "message": "Policy updated"})
        else:
            self._respond_json(404, {"error": f"Policy not found: {policy_id}"})

    # ── Policy Sync API ──────────────────────────────────────────────────

    def _handle_sync_all(self):
        """POST /policies/sync — sync from all 3 sources."""
        if not _HAS_POLICY_SYNC:
            self._respond_json(501, {"error": "Policy sync module not available"})
            return
        result = sync_all()
        self._respond_json(200, result)

    def _handle_sync_github(self):
        """POST /policies/sync/github — sync from GitHub community repo."""
        if not _HAS_POLICY_SYNC:
            self._respond_json(501, {"error": "Policy sync module not available"})
            return
        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length)) if content_length else {}
        result = sync_from_github(
            repo=body.get("repo"),
            branch=body.get("branch"),
            path=body.get("path"),
        )
        self._respond_json(200, result)

    def _handle_sync_cis(self):
        """POST /policies/sync/cis — sync from CIS benchmarks."""
        if not _HAS_POLICY_SYNC:
            self._respond_json(501, {"error": "Policy sync module not available"})
            return
        result = sync_from_cis()
        self._respond_json(200, result)

    def _handle_sync_prowler(self):
        """POST /policies/sync/prowler — sync from Prowler open-source."""
        if not _HAS_POLICY_SYNC:
            self._respond_json(501, {"error": "Policy sync module not available"})
            return
        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length)) if content_length else {}
        result = sync_from_prowler(provider=body.get("provider"))
        self._respond_json(200, result)

    def _handle_auto_generate(self):
        """POST /policies/auto-generate — generate policy from event."""
        if not _HAS_POLICY_GENERATOR:
            self._respond_json(501, {"error": "Policy generator not available"})
            return
        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length)) if content_length else {}
        policy = auto_generate_policy(body)
        if policy:
            self._respond_json(201, {"policy": policy, "message": "Policy auto-generated"})
        else:
            self._respond_json(200, {"message": "Policy already exists or could not be generated"})

    def _handle_simulate(self):
        """POST /simulate — run one targeted attack on demand.

        Body: {"type": "s3_public"|"s3_encrypt"|"iam"|"sg"|"dynamodb",
               "target": <optional resource name>,
               "account": <optional account id>,
               "region": <optional region>}

        This is what lets a second actor (a teammate, a script, a red-team
        exercise) trigger a specific attack against a running dashboard,
        instead of the dashboard only ever showing scripts/simulate-attacks.py's
        fixed demo sequence — "defense watches while someone else attacks"
        is a stronger live demo than a canned script, and doubles as evidence
        the detection layer isn't just replaying fixtures."""
        content_length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(content_length)) if content_length else {}
        except json.JSONDecodeError as exc:
            self._respond_json(400, {"error": f"Invalid JSON body: {exc}"})
            return

        attack_type = body.get("type")
        simulator = _get_attack_simulator()
        if simulator is None:
            self._respond_json(501, {
                "error": "Attack simulator not available",
                "detail": _attack_simulator_import_error or "unknown import failure",
            })
            return
        if attack_type not in simulator.TARGETED_ATTACK_TYPES:
            self._respond_json(400, {
                "error": f"'type' must be one of {simulator.TARGETED_ATTACK_TYPES}, got {attack_type!r}",
            })
            return

        try:
            result = simulator.run_targeted_attack(
                attack_type, target=body.get("target"),
                account=body.get("account"), region=body.get("region"),
            )
            self._respond_json(200, result)
        except Exception as exc:
            print(f"  [ERROR] /simulate failed: {exc}")
            self._respond_json(500, {"error": str(exc)})

    # ── Multi-Cloud Scan API ───────────────────────────────────────────────

    def _handle_scan(self, provider_slug):
        """GET /scan/<provider> — run security checks against a cloud provider."""
        if not _HAS_CLOUD_PROVIDERS:
            self._respond_json(501, {"error": "Cloud provider module not available"})
            return

        try:
            provider = get_provider(provider_slug)
        except ValueError as exc:
            self._respond_json(400, {"error": str(exc)})
            return

        checks = [
            ("check_storage_public_access", "Storage Public Access"),
            ("check_storage_encryption", "Storage Encryption"),
            ("check_network_open_ports", "Network Open Ports"),
            ("check_iam_overpermissive", "IAM Overpermissive"),
        ]

        results = []
        for check_name, label in checks:
            try:
                method = getattr(provider, check_name)
                # Use 'all' as default resource to scan everything
                result = method("all")
                result["check"] = label
                results.append(result)
            except Exception as exc:
                results.append({
                    "check": label,
                    "status": "ERROR",
                    "provider": provider_slug,
                    "message": str(exc),
                })

        compliant = len([r for r in results if r.get("status") == "COMPLIANT"])
        non_compliant = len([r for r in results if r.get("status") == "NON_COMPLIANT"])
        errors = len([r for r in results if r.get("status") == "ERROR"])

        self._respond_json(200, {
            "provider": provider_slug,
            "provider_name": provider.NAME,
            "results": results,
            "summary": {
                "total_checks": len(results),
                "compliant": compliant,
                "non_compliant": non_compliant,
                "errors": errors,
            },
        })

    # ── Helpers ─────────────────────────────────────────────────────────

    def _respond_json(self, status, body):
        self.send_response(status)
        self._add_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body, default=str).encode())

    def _add_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, format, *args):
        print(f"  [{self.log_date_time_string()}] {args[0]}")


def main():
    print()
    print("=" * 55)
    print("  🛡️  CSPM Dashboard — Local Server")
    print("=" * 55)
    print()
    print(f"  Dashboard:   http://localhost:{SERVER_PORT}")
    print(f"  API /stats:  http://localhost:{SERVER_PORT}/stats")
    print(f"  API /events: http://localhost:{SERVER_PORT}/events")
    print(f"  Policies:    http://localhost:{SERVER_PORT}/policies")
    print(f"  Sync:        POST /policies/sync")
    print(f"  Providers:   http://localhost:{SERVER_PORT}/providers")
    print(f"  Scan Azure:  http://localhost:{SERVER_PORT}/scan/azure")
    print(f"  Scan GCP:    http://localhost:{SERVER_PORT}/scan/gcp")
    print(f"  GitHub:      POST /create-issues")
    print(f"  Frontend:    {FRONTEND_DIR}")
    print(f"  LocalStack:  {LOCALSTACK_ENDPOINT}")
    print()
    print("  Open http://localhost:3001 in your browser!")
    print("  Press Ctrl+C to stop.")
    print()

    server = ThreadingHTTPServer(("0.0.0.0", SERVER_PORT), CSPMHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
