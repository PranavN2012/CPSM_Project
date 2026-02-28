"""
CSPM Dashboard API Lambda

Serves remediation event data from DynamoDB for the security dashboard frontend.
Deployed behind API Gateway (HTTP API) with CORS enabled.
"""

import json
import logging
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
import os

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DYNAMODB_TABLE_NAME: str = os.environ.get("DYNAMODB_TABLE_NAME", "cspm-remediation-events")
ALLOWED_ORIGIN: str = os.environ.get("ALLOWED_ORIGIN", "*")

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(DYNAMODB_TABLE_NAME)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cors_headers() -> dict[str, str]:
    """Return standard CORS headers for API responses."""
    return {
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }


def _response(status_code: int, body: Any) -> dict[str, Any]:
    """
    Build a standardised API Gateway proxy response.

    Args:
        status_code: HTTP status code.
        body: Response body (will be JSON-serialised).

    Returns:
        dict compatible with API Gateway Lambda proxy integration.
    """
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


# ---------------------------------------------------------------------------
# Route Handlers
# ---------------------------------------------------------------------------

def get_events() -> dict[str, Any]:
    """
    Retrieve all remediation events from DynamoDB, sorted by timestamp descending.

    Returns:
        API response containing a list of remediation event records.
    """
    try:
        response = table.scan()
        items = response.get("Items", [])

        # Handle pagination for large datasets
        while "LastEvaluatedKey" in response:
            response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response.get("Items", []))

        # Sort by timestamp descending
        items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        logger.info("Retrieved %d events from DynamoDB.", len(items))
        return _response(200, {"events": items, "count": len(items)})

    except ClientError as exc:
        logger.error("DynamoDB scan failed: %s", exc)
        return _response(500, {"error": "Failed to retrieve events"})


def get_stats() -> dict[str, Any]:
    """
    Compute aggregate statistics including vulnerability type breakdown.
    """
    try:
        response = table.scan()
        items = response.get("Items", [])

        while "LastEvaluatedKey" in response:
            response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response.get("Items", []))

        total = len(items)
        remediated = sum(1 for i in items if i.get("status") in
                         ("REMEDIATED", "ENCRYPTION_REMEDIATED"))
        compliant = sum(1 for i in items if i.get("status") == "COMPLIANT")
        failed = sum(1 for i in items if i.get("status") in
                     ("REMEDIATION_FAILED", "ENCRYPTION_FAILED"))
        flagged = sum(1 for i in items if i.get("status") == "IAM_OVERPERMISSIVE")
        unique_buckets = len(set(i.get("bucket_name", "") for i in items))
        unique_regions = list(set(i.get("region", "") for i in items))
        last_event = max((i.get("timestamp", "") for i in items), default="N/A")

        # Vulnerability type breakdown
        vuln_types = {}
        for item in items:
            vt = item.get("vulnerability_type", "S3 Public Access")
            vuln_types[vt] = vuln_types.get(vt, 0) + 1

        # Severity breakdown
        severities = {}
        for item in items:
            sev = item.get("severity", "MEDIUM")
            severities[sev] = severities.get(sev, 0) + 1

        # Compliance rate
        actionable = remediated + failed + flagged
        compliance_rate = round((remediated / actionable * 100), 1) if actionable > 0 else 100.0

        stats = {
            "total_events": total,
            "remediated": remediated,
            "compliant": compliant,
            "failed": failed,
            "flagged": flagged,
            "unique_buckets": unique_buckets,
            "active_regions": unique_regions,
            "last_event": last_event,
            "compliance_rate": compliance_rate,
            "vulnerability_types": vuln_types,
            "severities": severities,
        }

        logger.info("Computed stats: %s", stats)
        return _response(200, stats)

    except ClientError as exc:
        logger.error("DynamoDB scan failed: %s", exc)
        return _response(500, {"error": "Failed to compute stats"})


def get_compliance() -> dict[str, Any]:
    """Compute compliance framework scores."""
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
        from compliance import get_compliance_summary

        response = table.scan()
        items = response.get("Items", [])
        while "LastEvaluatedKey" in response:
            response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response.get("Items", []))

        summary = get_compliance_summary(items)
        return _response(200, summary)

    except Exception as exc:
        logger.error("Compliance computation failed: %s", exc)
        return _response(500, {"error": str(exc)})


def get_trends() -> dict[str, Any]:
    """Compute daily compliance scores for trend chart."""
    try:
        response = table.scan()
        items = response.get("Items", [])
        while "LastEvaluatedKey" in response:
            response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response.get("Items", []))

        # Group events by date
        daily = {}
        for item in items:
            date = item.get("timestamp", "")[:10]
            if not date:
                continue
            if date not in daily:
                daily[date] = {"total": 0, "remediated": 0}
            daily[date]["total"] += 1
            if item.get("status") in ("REMEDIATED", "ENCRYPTION_REMEDIATED", "COMPLIANT"):
                daily[date]["remediated"] += 1

        # Compute daily scores
        trend_data = []
        for date in sorted(daily.keys()):
            d = daily[date]
            score = round(d["remediated"] / d["total"] * 100, 1) if d["total"] > 0 else 0
            trend_data.append({"date": date, "score": score, "events": d["total"]})

        return _response(200, {"trends": trend_data})

    except Exception as exc:
        logger.error("Trends computation failed: %s", exc)
        return _response(500, {"error": str(exc)})


# ---------------------------------------------------------------------------
# Lambda Handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Main entry point for the Dashboard API Lambda."""
    logger.info("API request: %s", json.dumps(event, default=str))

    http_method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    if http_method == "OPTIONS":
        return _response(200, {"message": "OK"})

    raw_path = event.get("rawPath", "/")
    path = raw_path.rstrip("/")

    routes: dict[str, Any] = {
        "/events": get_events,
        "/stats": get_stats,
        "/compliance": get_compliance,
        "/trends": get_trends,
    }

    handler = routes.get(path)
    if handler:
        return handler()

    return _response(404, {"error": f"Route not found: {path}"})

