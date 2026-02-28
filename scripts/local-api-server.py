"""
local-api-server.py — All-in-One CSPM Dashboard Server
======================================================
Serves the frontend (HTML/CSS/JS) AND proxies API calls to the Lambda
functions on LocalStack — all on a single port.

Also handles GitHub Issue creation via /create-issues endpoint.

One command, one URL, real data.

Usage:
    python scripts/local-api-server.py

Then open: http://localhost:3000
"""

import json
import os
import sys
import mimetypes
import http.server
import urllib.parse
import threading
import boto3

LOCALSTACK_ENDPOINT = "http://localhost:4566"
API_LAMBDA_NAME = "cspm-s3-remediation-api"
SERVER_PORT = 3000
REGION = "us-east-1"

# GitHub config
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = "PranavN2012/CPSM_Project"

# Resolve the frontend directory relative to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "frontend"))

lambda_client = boto3.client(
    "lambda",
    endpoint_url=LOCALSTACK_ENDPOINT,
    region_name=REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
)


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

        # ── Static frontend files ──
        self._serve_static(path)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/create-issues":
            self._handle_create_issues()
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
        # Map / to /index.html
        if path == "/":
            path = "/index.html"

        # Security: prevent directory traversal
        safe_path = os.path.normpath(path.lstrip("/"))
        file_path = os.path.join(FRONTEND_DIR, safe_path)
        file_path = os.path.normpath(file_path)

        if not file_path.startswith(FRONTEND_DIR):
            self._respond_json(403, {"error": "Forbidden"})
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

    # ── Helpers ─────────────────────────────────────────────────────────

    def _respond_json(self, status, body):
        self.send_response(status)
        self._add_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body, default=str).encode())

    def _add_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, format, *args):
        print(f"  [{self.log_date_time_string()}] {args[0]}")


def main():
    print()
    print("=" * 55)
    print("  🛡️  CSPM Dashboard — Local Server")
    print("=" * 55)
    print()
    print(f"  Dashboard:  http://localhost:{SERVER_PORT}")
    print(f"  API /stats: http://localhost:{SERVER_PORT}/stats")
    print(f"  API /events:http://localhost:{SERVER_PORT}/events")
    print(f"  GitHub:     POST /create-issues")
    print(f"  Frontend:   {FRONTEND_DIR}")
    print(f"  LocalStack: {LOCALSTACK_ENDPOINT}")
    print()
    print("  Open http://localhost:3000 in your browser!")
    print("  Press Ctrl+C to stop.")
    print()

    server = http.server.HTTPServer(("0.0.0.0", SERVER_PORT), CSPMHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
