"""
CSPM S3 Remediation Lambda — Multi-Vulnerability Edition
=========================================================

Detects and remediates:
  1. S3 Public Access — buckets with public access block disabled
  2. S3 Encryption — buckets without default server-side encryption

Triggered by EventBridge rules monitoring CloudTrail for S3 config changes.
Logs events to DynamoDB, sends Discord webhooks, and creates GitHub Issues.
"""

import json
import os
import sys
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3
import urllib3
from botocore.exceptions import ClientError

# Add shared modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

try:
    from github_notifier import create_github_issue
except ImportError:
    def create_github_issue(**kwargs):
        pass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DISCORD_WEBHOOK_URL: str = os.environ.get("DISCORD_WEBHOOK_URL", "")
DYNAMODB_TABLE_NAME: str = os.environ.get("DYNAMODB_TABLE_NAME", "cspm-remediation-events")

s3_client = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
http = urllib3.PoolManager()


# ---------------------------------------------------------------------------
# Main Handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Entry point — runs all S3 security checks on the affected bucket.
    """
    logger.info("Received event: %s", json.dumps(event, default=str))

    try:
        detail = event.get("detail", {})
        bucket_name = _extract_bucket_name(detail)
        account_id = event.get("account", detail.get("recipientAccountId", "unknown"))
        region = event.get("region", detail.get("awsRegion", "unknown"))
        event_name = detail.get("eventName", "unknown")

        logger.info("Processing '%s' for bucket '%s' [%s/%s]",
                     event_name, bucket_name, account_id, region)
    except (KeyError, TypeError, ValueError) as exc:
        logger.error("Failed to parse event: %s", exc)
        return {"statusCode": 400, "body": f"Bad event format: {exc}"}

    results = []

    # ── Check 1: Public Access ──
    pa_result = check_public_access(bucket_name, account_id, region, event_name)
    if pa_result:
        results.append(pa_result)

    # ── Check 2: Encryption ──
    enc_result = check_encryption(bucket_name, account_id, region, event_name)
    if enc_result:
        results.append(enc_result)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "bucket": bucket_name,
            "checks": results,
            "status": results[0]["status"] if results else "SKIPPED",
        }),
    }


# ---------------------------------------------------------------------------
# Check 1: S3 Public Access
# ---------------------------------------------------------------------------

def check_public_access(bucket_name, account_id, region, event_name):
    """Check and remediate S3 public access."""
    config = inspect_public_access(bucket_name)
    if config is None:
        return None

    needs_fix = not all([
        config.get("BlockPublicAcls", False),
        config.get("IgnorePublicAcls", False),
        config.get("BlockPublicPolicy", False),
        config.get("RestrictPublicBuckets", False),
    ])

    if needs_fix:
        success = remediate_public_access(bucket_name)
        status = "REMEDIATED" if success else "REMEDIATION_FAILED"
        severity = "CRITICAL"
    else:
        status = "COMPLIANT"
        severity = "LOW"

    vuln_type = "S3 Public Access"

    log_event_to_dynamodb(
        bucket_name=bucket_name, account_id=account_id, region=region,
        status=status, event_name=event_name, vulnerability_type=vuln_type,
        severity=severity,
    )

    if needs_fix:
        send_discord_notification(
            bucket_name=bucket_name, account_id=account_id, region=region,
            status=status, vulnerability_type=vuln_type, severity=severity,
        )
        create_github_issue(
            title=f"🛡️ S3 Public Access: {bucket_name} [{status}]",
            vulnerability_type=vuln_type, resource_name=bucket_name,
            account_id=account_id, region=region, status=status, severity=severity,
            details=f"Bucket `{bucket_name}` had public access block disabled. "
                    f"CSPM auto-remediated by enabling all 4 public access block flags.",
        )

    return {"check": vuln_type, "status": status, "severity": severity}


# ---------------------------------------------------------------------------
# Check 2: S3 Encryption
# ---------------------------------------------------------------------------

def check_encryption(bucket_name, account_id, region, event_name):
    """Check and remediate S3 default encryption."""
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            # Encryption exists
            log_event_to_dynamodb(
                bucket_name=bucket_name, account_id=account_id, region=region,
                status="COMPLIANT", event_name=event_name,
                vulnerability_type="S3 Encryption", severity="LOW",
            )
            return {"check": "S3 Encryption", "status": "COMPLIANT", "severity": "LOW"}
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code in ("ServerSideEncryptionConfigurationNotFoundError",
                          "NoSuchEncryptionConfiguration"):
            # No encryption — remediate
            pass
        elif error_code in ("NoSuchBucket", "AccessDenied"):
            return None
        else:
            logger.error("Unexpected error checking encryption for '%s': %s", bucket_name, exc)
            return None

    # Remediate: enable AES-256 default encryption
    status = "ENCRYPTION_REMEDIATED"
    severity = "HIGH"
    vuln_type = "S3 Encryption"

    try:
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    },
                    "BucketKeyEnabled": True,
                }]
            },
        )
        logger.info("Enabled AES-256 encryption on bucket '%s'.", bucket_name)
    except ClientError as exc:
        logger.error("Failed to enable encryption on '%s': %s", bucket_name, exc)
        status = "ENCRYPTION_FAILED"

    log_event_to_dynamodb(
        bucket_name=bucket_name, account_id=account_id, region=region,
        status=status, event_name=event_name, vulnerability_type=vuln_type,
        severity=severity,
    )

    send_discord_notification(
        bucket_name=bucket_name, account_id=account_id, region=region,
        status=status, vulnerability_type=vuln_type, severity=severity,
    )

    create_github_issue(
        title=f"🔐 S3 Encryption: {bucket_name} [{status}]",
        vulnerability_type=vuln_type, resource_name=bucket_name,
        account_id=account_id, region=region, status=status, severity=severity,
        details=f"Bucket `{bucket_name}` had no default server-side encryption. "
                f"CSPM auto-enabled AES-256 (SSE-S3) encryption.",
    )

    return {"check": vuln_type, "status": status, "severity": severity}


# ---------------------------------------------------------------------------
# S3 Inspection & Remediation Helpers
# ---------------------------------------------------------------------------

def _extract_bucket_name(detail: dict[str, Any]) -> str:
    request_params = detail.get("requestParameters", {})
    if request_params and "bucketName" in request_params:
        return request_params["bucketName"]
    resources = detail.get("resources", [])
    for resource in resources:
        arn = resource.get("ARN", "")
        if ":s3:::" in arn:
            return arn.split(":::")[-1]
    raise ValueError("Could not extract bucket name from event detail")


def inspect_public_access(bucket_name: str) -> dict[str, bool] | None:
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        return response.get("PublicAccessBlockConfiguration", {})
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "NoSuchPublicAccessConfiguration":
            return {
                "BlockPublicAcls": False, "IgnorePublicAcls": False,
                "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
            }
        if error_code in ("NoSuchBucket", "AccessDenied"):
            return None
        return None


def remediate_public_access(bucket_name: str) -> bool:
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            },
        )
        logger.info("Remediated public access on '%s'.", bucket_name)
        return True
    except ClientError as exc:
        logger.error("Failed to remediate '%s': %s", bucket_name, exc)
        return False


# ---------------------------------------------------------------------------
# Logging & Notifications
# ---------------------------------------------------------------------------

def log_event_to_dynamodb(
    bucket_name, account_id, region, status, event_name,
    vulnerability_type="S3 Public Access", severity="HIGH",
):
    try:
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        table.put_item(Item={
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "bucket_name": bucket_name,
            "account_id": account_id,
            "region": region,
            "status": status,
            "event_name": event_name,
            "vulnerability_type": vulnerability_type,
            "severity": severity,
        })
    except ClientError as exc:
        logger.error("DynamoDB write failed: %s", exc)


def send_discord_notification(
    bucket_name, account_id, region, status,
    vulnerability_type="S3 Public Access", severity="HIGH",
):
    if not DISCORD_WEBHOOK_URL:
        logger.warning("DISCORD_WEBHOOK_URL not set — skipping.")
        return

    color_map = {
        "REMEDIATED": 0x2ECC71, "ENCRYPTION_REMEDIATED": 0x2ECC71,
        "REMEDIATION_FAILED": 0xE74C3C, "ENCRYPTION_FAILED": 0xE74C3C,
        "COMPLIANT": 0x3498DB,
    }
    icon_map = {
        "S3 Public Access": "🛡️",
        "S3 Encryption": "🔐",
        "IAM Audit": "👤",
    }

    color = color_map.get(status, 0x95A5A6)
    icon = icon_map.get(vulnerability_type, "🔍")

    embed = {
        "title": f"{icon} CSPM — {vulnerability_type}",
        "color": color,
        "fields": [
            {"name": "🪣 Resource", "value": f"`{bucket_name}`", "inline": True},
            {"name": "🏢 Account", "value": f"`{account_id}`", "inline": True},
            {"name": "🌎 Region", "value": f"`{region}`", "inline": True},
            {"name": "📋 Status", "value": f"**{status}**", "inline": True},
            {"name": "⚠️ Severity", "value": f"**{severity}**", "inline": True},
        ],
        "footer": {"text": "Serverless CSPM • Automated Remediation"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    payload = json.dumps({"embeds": [embed]}).encode("utf-8")
    try:
        response = http.request("POST", DISCORD_WEBHOOK_URL, body=payload,
                                headers={"Content-Type": "application/json"})
        if response.status in (200, 204):
            logger.info("Discord notification sent.")
        else:
            logger.warning("Discord returned %s", response.status)
    except Exception as exc:
        logger.error("Discord notification failed: %s", exc)
