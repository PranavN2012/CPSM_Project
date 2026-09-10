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

try:
    from nlg_engine import generate_incident_summary
except ImportError:
    def generate_incident_summary(**kwargs):
        return ""

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DISCORD_WEBHOOK_URL: str = os.environ.get("DISCORD_WEBHOOK_URL", "")
DYNAMODB_TABLE_NAME: str = os.environ.get("DYNAMODB_TABLE_NAME", "cspm-remediation-events")

s3_client = boto3.client("s3")
ec2_client = boto3.client("ec2")
dynamodb_client = boto3.client("dynamodb")
dynamodb = boto3.resource("dynamodb")
http = urllib3.PoolManager()


# ---------------------------------------------------------------------------
# Main Handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Entry point — routes event to appropriate security checks.
    """
    logger.info("Received event: %s", json.dumps(event, default=str))

    try:
        detail = event.get("detail", {})
        if "eventSource" not in detail:
            raise ValueError("event.detail is missing required field 'eventSource'")
        account_id = event.get("account", detail.get("recipientAccountId", "unknown"))
        region = event.get("region", detail.get("awsRegion", "unknown"))
        event_name = detail.get("eventName", "unknown")
        event_source = detail["eventSource"]
    except (KeyError, TypeError, ValueError) as exc:
        logger.error("Failed to parse event: %s", exc)
        return {"statusCode": 400, "body": f"Bad event format: {exc}"}

    results = []
    resource_id = "unknown"

    # Resource extraction can raise ValueError for a well-formed-but-incomplete
    # event (e.g. an s3.amazonaws.com event with no bucketName) — caught here
    # and reported as a clean 400, the same as the initial event-parsing step
    # above, instead of propagating as an unhandled exception.
    try:
        if event_source == "s3.amazonaws.com":
            resource_id = _extract_bucket_name(detail)
        elif event_source == "ec2.amazonaws.com":
            resource_id = _extract_sg_id(detail)
        elif event_source == "dynamodb.amazonaws.com":
            resource_id = _extract_table_name(detail)
    except ValueError as exc:
        logger.error("Failed to extract resource identifier: %s", exc)
        return {"statusCode": 400, "body": f"Bad event format: {exc}"}

    if event_source == "s3.amazonaws.com":
        logger.info("Processing '%s' for bucket '%s'", event_name, resource_id)
        # ── Check 1: Public Access ──
        pa_result = check_public_access(resource_id, account_id, region, event_name)
        if pa_result: results.append(pa_result)
        # ── Check 2: Encryption ──
        enc_result = check_encryption(resource_id, account_id, region, event_name)
        if enc_result: results.append(enc_result)

    elif event_source == "ec2.amazonaws.com":
        logger.info("Processing '%s' for security group '%s'", event_name, resource_id)
        sg_result = check_security_group(resource_id, account_id, region, event_name)
        if sg_result: results.append(sg_result)

    elif event_source == "dynamodb.amazonaws.com":
        logger.info("Processing '%s' for DDB table '%s'", event_name, resource_id)
        ddb_result = check_dynamodb_encryption(resource_id, account_id, region, event_name)
        if ddb_result: results.append(ddb_result)

    else:
        logger.warning("Unsupported event source: %s", event_source)
        return {"statusCode": 200, "body": json.dumps({"status": "SKIPPED"})}

    return {
        "statusCode": 200,
        "body": json.dumps({
            "resource": resource_id,
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

    nlp_summary = generate_incident_summary(
        resource_name=bucket_name, account_id=account_id, region=region,
        status=status, event_name=event_name, vulnerability_type=vuln_type,
        severity=severity, dynamodb_table=dynamodb.Table(DYNAMODB_TABLE_NAME),
    )

    log_event_to_dynamodb(
        bucket_name=bucket_name, account_id=account_id, region=region,
        status=status, event_name=event_name, vulnerability_type=vuln_type,
        severity=severity, nlp_summary=nlp_summary,
    )

    if needs_fix:
        send_discord_notification(
            bucket_name=bucket_name, account_id=account_id, region=region,
            status=status, vulnerability_type=vuln_type, severity=severity,
            nlp_summary=nlp_summary,
        )
        create_github_issue(
            title=f"🛡️ S3 Public Access: {bucket_name} [{status}]",
            vulnerability_type=vuln_type, resource_name=bucket_name,
            account_id=account_id, region=region, status=status, severity=severity,
            details=nlp_summary,
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
            nlp_summary = generate_incident_summary(
                resource_name=bucket_name, account_id=account_id, region=region,
                status="COMPLIANT", event_name=event_name,
                vulnerability_type="S3 Encryption", severity="LOW",
                dynamodb_table=dynamodb.Table(DYNAMODB_TABLE_NAME),
            )
            log_event_to_dynamodb(
                bucket_name=bucket_name, account_id=account_id, region=region,
                status="COMPLIANT", event_name=event_name,
                vulnerability_type="S3 Encryption", severity="LOW",
                nlp_summary=nlp_summary,
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

    nlp_summary = generate_incident_summary(
        resource_name=bucket_name, account_id=account_id, region=region,
        status=status, event_name=event_name, vulnerability_type=vuln_type,
        severity=severity, dynamodb_table=dynamodb.Table(DYNAMODB_TABLE_NAME),
    )

    log_event_to_dynamodb(
        bucket_name=bucket_name, account_id=account_id, region=region,
        status=status, event_name=event_name, vulnerability_type=vuln_type,
        severity=severity, nlp_summary=nlp_summary,
    )

    send_discord_notification(
        bucket_name=bucket_name, account_id=account_id, region=region,
        status=status, vulnerability_type=vuln_type, severity=severity,
        nlp_summary=nlp_summary,
    )

    create_github_issue(
        title=f"🔐 S3 Encryption: {bucket_name} [{status}]",
        vulnerability_type=vuln_type, resource_name=bucket_name,
        account_id=account_id, region=region, status=status, severity=severity,
        details=nlp_summary,
    )

    return {"check": vuln_type, "status": status, "severity": severity}


# ---------------------------------------------------------------------------
# Check 3: Security Group SSH 
# ---------------------------------------------------------------------------

def check_security_group(sg_id, account_id, region, event_name):
    """Check and remediate open SSH ingress."""
    try:
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
        sg = response["SecurityGroups"][0]
    except Exception as exc:
        logger.error("Failed to describe SG '%s': %s", sg_id, exc)
        return None

    needs_remediation = False
    offending_permissions = []
    
    for perm in sg.get("IpPermissions", []):
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        ip_ranges = perm.get("IpRanges", [])
        ipv6_ranges = perm.get("Ipv6Ranges", [])

        if from_port == 22 or to_port == 22 or (from_port is None and to_port is None):
            is_open_v4 = any(ipr.get("CidrIp") == "0.0.0.0/0" for ipr in ip_ranges)
            is_open_v6 = any(ipr.get("CidrIpv6") == "::/0" for ipr in ipv6_ranges)
            if is_open_v4 or is_open_v6:
                needs_remediation = True
                offending_permissions.append(perm)
                    
    status = "COMPLIANT"
    severity = "LOW"
    vuln_type = "Security Group Open SSH"
    
    if needs_remediation:
        severity = "HIGH"
        try:
            ec2_client.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=offending_permissions
            )
            logger.info("Revoked open SSH on SG '%s'.", sg_id)
            status = "REMEDIATED"
        except Exception as exc:
            logger.error("Failed to remediate SG '%s': %s", sg_id, exc)
            status = "REMEDIATION_FAILED"

    nlp_summary = generate_incident_summary(
        resource_name=sg_id, account_id=account_id, region=region,
        status=status, event_name=event_name, vulnerability_type=vuln_type,
        severity=severity, dynamodb_table=dynamodb.Table(DYNAMODB_TABLE_NAME),
    )

    log_event_to_dynamodb(
        bucket_name=sg_id, account_id=account_id, region=region,
        status=status, event_name=event_name, vulnerability_type=vuln_type,
        severity=severity, nlp_summary=nlp_summary,
    )

    if needs_remediation:
        send_discord_notification(
            bucket_name=sg_id, account_id=account_id, region=region,
            status=status, vulnerability_type=vuln_type, severity=severity,
            nlp_summary=nlp_summary,
        )
        create_github_issue(
            title=f"🔒 SG SSH Access: {sg_id} [{status}]",
            vulnerability_type=vuln_type, resource_name=sg_id,
            account_id=account_id, region=region, status=status, severity=severity,
            details=nlp_summary,
        )

    return {"check": vuln_type, "status": status, "severity": severity}


# ---------------------------------------------------------------------------
# Check 4: DynamoDB Encryption
# ---------------------------------------------------------------------------

def check_dynamodb_encryption(table_name, account_id, region, event_name):
    """Check and remediate DynamoDB unencrypted tables."""
    try:
        # LocalStack / AWS DDB usually has SSEDescription if encrypted with KMS
        response = dynamodb_client.describe_table(TableName=table_name)
        sse_desc = response["Table"].get("SSEDescription", {})
        
        # If SSE is missing or status is not ENABLED, it relies on AWS owned default setting.
        # We enforce explicitly enabling KMS (Customer Managed or AWS Managed algos)
        sse_status = sse_desc.get("Status")
        if sse_status == "ENABLED":
            nlp_summary = generate_incident_summary(
                resource_name=table_name, account_id=account_id, region=region,
                status="COMPLIANT", event_name=event_name,
                vulnerability_type="DynamoDB Unencrypted", severity="LOW",
                dynamodb_table=dynamodb.Table(DYNAMODB_TABLE_NAME),
            )
            log_event_to_dynamodb(
                bucket_name=table_name, account_id=account_id, region=region,
                status="COMPLIANT", event_name=event_name,
                vulnerability_type="DynamoDB Unencrypted", severity="LOW",
                nlp_summary=nlp_summary,
            )
            return {"check": "DynamoDB Unencrypted", "status": "COMPLIANT", "severity": "LOW"}
            
    except Exception as exc:
        logger.error("Failed to describe DDB table '%s': %s", table_name, exc)
        return None

    status = "ENCRYPTION_REMEDIATED"
    severity = "MEDIUM"
    vuln_type = "DynamoDB Unencrypted"
    
    try:
        dynamodb_client.update_table(
            TableName=table_name,
            SSESpecification={
                "Enabled": True,
                "SSEType": "KMS"
            }
        )
        logger.info("Enabled KMS encryption on DynamoDB table '%s'.", table_name)
    except Exception as exc:
        logger.error("Failed to encrypt DDB table '%s': %s", table_name, exc)
        status = "ENCRYPTION_FAILED"

    nlp_summary = generate_incident_summary(
        resource_name=table_name, account_id=account_id, region=region,
        status=status, event_name=event_name, vulnerability_type=vuln_type,
        severity=severity, dynamodb_table=dynamodb.Table(DYNAMODB_TABLE_NAME),
    )

    log_event_to_dynamodb(
        bucket_name=table_name, account_id=account_id, region=region,
        status=status, event_name=event_name, vulnerability_type=vuln_type,
        severity=severity, nlp_summary=nlp_summary,
    )

    send_discord_notification(
        bucket_name=table_name, account_id=account_id, region=region,
        status=status, vulnerability_type=vuln_type, severity=severity,
        nlp_summary=nlp_summary,
    )

    create_github_issue(
        title=f"🔐 DynamoDB Encryption: {table_name} [{status}]",
        vulnerability_type=vuln_type, resource_name=table_name,
        account_id=account_id, region=region, status=status, severity=severity,
        details=nlp_summary,
    )

    return {"check": vuln_type, "status": status, "severity": severity}


# ---------------------------------------------------------------------------
# Inspection & Extraction Helpers
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

def _extract_sg_id(detail: dict[str, Any]) -> str:
    request_params = detail.get("requestParameters", {})
    if request_params and "groupId" in request_params:
        return request_params["groupId"]
    raise ValueError("Could not extract SG ID from event detail")

def _extract_table_name(detail: dict[str, Any]) -> str:
    request_params = detail.get("requestParameters", {})
    if request_params and "tableName" in request_params:
        return request_params["tableName"]
    raise ValueError("Could not extract DynamoDB table name from event detail")


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
    nlp_summary="",
):
    try:
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        item = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "bucket_name": bucket_name,
            "account_id": account_id,
            "region": region,
            "status": status,
            "event_name": event_name,
            "vulnerability_type": vulnerability_type,
            "severity": severity,
        }
        if nlp_summary:
            item["nlp_summary"] = nlp_summary
        table.put_item(Item=item)
    except ClientError as exc:
        logger.error("DynamoDB write failed: %s", exc)


def send_discord_notification(
    bucket_name, account_id, region, status,
    vulnerability_type="S3 Public Access", severity="HIGH",
    nlp_summary="",
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
        "Security Group Open SSH": "🔒",
        "DynamoDB Unencrypted": "🔐",
    }

    color = color_map.get(status, 0x95A5A6)
    icon = icon_map.get(vulnerability_type, "🔍")

    fields = [
            {"name": "🪣 Resource", "value": f"`{bucket_name}`", "inline": True},
            {"name": "🏢 Account", "value": f"`{account_id}`", "inline": True},
            {"name": "🌎 Region", "value": f"`{region}`", "inline": True},
            {"name": "📋 Status", "value": f"**{status}**", "inline": True},
            {"name": "⚠️ Severity", "value": f"**{severity}**", "inline": True},
    ]
    if nlp_summary:
        fields.append({"name": "🧠 AI Incident Summary", "value": nlp_summary[:1024], "inline": False})

    embed = {
        "title": f"{icon} CSPM — {vulnerability_type}",
        "color": color,
        "fields": fields,
        "footer": {"text": "Serverless CSPM • Automated Remediation • NLG Engine v1.0"},
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
