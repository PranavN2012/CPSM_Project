"""
CSPM IAM Audit Lambda
======================

Scans all IAM policies for overly permissive configurations:
  - Wildcard (*) actions
  - Wildcard (*) resources
  - Admin-level policies attached to users

Flags findings without auto-remediation (IAM changes are too risky to automate).
Logs events to DynamoDB, sends Discord alerts, and creates GitHub Issues.
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

iam_client = boto3.client("iam")
dynamodb = boto3.resource("dynamodb")
http = urllib3.PoolManager()


# ---------------------------------------------------------------------------
# Main Handler
# ---------------------------------------------------------------------------

def _unresolved_iam_audit_resources() -> set:
    """Resources that already have a logged, not-yet-fixed IAM Audit
    finding. Used to skip re-logging a duplicate event every time the scan
    runs against a still-broken identity — previously every scan logged a
    fresh event for a persistently overpermissive identity even though
    nothing about it had changed since the last scan, inflating the event
    log (and permanently dragging the compliance score) with duplicates of
    the same unresolved problem. Logging resumes normally once the
    identity's status changes away from IAM_OVERPERMISSIVE (fixed, or
    flagged again after a genuine regression)."""
    try:
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        resp = table.scan(
            FilterExpression="vulnerability_type = :vt AND #s = :st",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":vt": "IAM Audit", ":st": "IAM_OVERPERMISSIVE"},
        )
        return {item["bucket_name"] for item in resp.get("Items", [])}
    except ClientError:
        return set()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Scans IAM policies and reports overly permissive configurations.
    Can be triggered on schedule or manually.
    """
    logger.info("Starting IAM audit scan...")

    already_flagged = _unresolved_iam_audit_resources()
    findings = []

    # Scan all IAM users
    try:
        users = iam_client.list_users().get("Users", [])
        for user in users:
            user_findings = audit_user_policies(user["UserName"])
            findings.extend(user_findings)
    except ClientError as exc:
        logger.error("Failed to list IAM users: %s", exc)

    # Scan all IAM roles
    try:
        roles = iam_client.list_roles().get("Roles", [])
        for role in roles:
            role_name = role["RoleName"]
            # Skip AWS service-linked roles
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            role_findings = audit_role_policies(role_name)
            findings.extend(role_findings)
    except ClientError as exc:
        logger.error("Failed to list IAM roles: %s", exc)

    # Log and notify for each finding
    account_id = event.get("account", "000000000000")
    region = event.get("region", "us-east-1")

    for finding in findings:
        if finding["resource"] in already_flagged:
            continue  # already logged and still unresolved — don't duplicate

        nlp_summary = generate_incident_summary(
            resource_name=finding["resource"],
            account_id=account_id,
            region=region,
            status="IAM_OVERPERMISSIVE",
            event_name="IAMAuditScan",
            vulnerability_type="IAM Audit",
            severity=finding["severity"],
            dynamodb_table=dynamodb.Table(DYNAMODB_TABLE_NAME),
            iam_policy_details=finding.get("details", ""),
        )

        log_event_to_dynamodb(
            bucket_name=finding["resource"],
            account_id=account_id,
            region=region,
            status="IAM_OVERPERMISSIVE",
            event_name="IAMAuditScan",
            vulnerability_type="IAM Audit",
            severity=finding["severity"],
            nlp_summary=nlp_summary,
        )

        send_discord_notification(
            resource=finding["resource"],
            account_id=account_id,
            region=region,
            status="IAM_OVERPERMISSIVE",
            details=finding["details"],
            severity=finding["severity"],
            nlp_summary=nlp_summary,
        )

        create_github_issue(
            title=f"👤 IAM Overpermissive: {finding['resource']}",
            vulnerability_type="IAM Audit",
            resource_name=finding["resource"],
            account_id=account_id,
            region=region,
            status="IAM_OVERPERMISSIVE",
            severity=finding["severity"],
            details=nlp_summary,
        )

    logger.info("IAM audit complete. Found %d issues.", len(findings))

    return {
        "statusCode": 200,
        "body": json.dumps({
            "scan": "IAM Audit",
            "findings_count": len(findings),
            "findings": findings,
        }),
    }


# ---------------------------------------------------------------------------
# Audit Functions
# ---------------------------------------------------------------------------

def audit_user_policies(username: str) -> list[dict]:
    """Audit inline and attached policies for a user."""
    findings = []

    # Check attached managed policies
    try:
        attached = iam_client.list_attached_user_policies(UserName=username)
        for policy in attached.get("AttachedPolicies", []):
            if is_admin_policy(policy["PolicyArn"]):
                findings.append({
                    "resource": f"User:{username}",
                    "severity": "CRITICAL",
                    "details": f"User `{username}` has admin-level managed policy "
                               f"`{policy['PolicyName']}` attached. "
                               f"This grants unrestricted access to all AWS services.",
                })
    except ClientError:
        pass

    # Check inline policies
    try:
        inline = iam_client.list_user_policies(UserName=username)
        for policy_name in inline.get("PolicyNames", []):
            try:
                policy_doc = iam_client.get_user_policy(
                    UserName=username, PolicyName=policy_name
                )["PolicyDocument"]
                wildcards = find_wildcards(policy_doc)
                if wildcards:
                    findings.append({
                        "resource": f"User:{username}",
                        "severity": "HIGH",
                        "details": f"User `{username}` inline policy `{policy_name}` "
                                   f"contains wildcards: {', '.join(wildcards)}",
                    })
            except ClientError:
                pass
    except ClientError:
        pass

    return findings


def audit_role_policies(role_name: str) -> list[dict]:
    """Audit inline and attached policies for a role."""
    findings = []

    try:
        attached = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached.get("AttachedPolicies", []):
            if is_admin_policy(policy["PolicyArn"]):
                findings.append({
                    "resource": f"Role:{role_name}",
                    "severity": "CRITICAL",
                    "details": f"Role `{role_name}` has admin-level managed policy "
                               f"`{policy['PolicyName']}` attached.",
                })
    except ClientError:
        pass

    try:
        inline = iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline.get("PolicyNames", []):
            try:
                policy_doc = iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )["PolicyDocument"]
                wildcards = find_wildcards(policy_doc)
                if wildcards:
                    findings.append({
                        "resource": f"Role:{role_name}",
                        "severity": "HIGH",
                        "details": f"Role `{role_name}` inline policy `{policy_name}` "
                                   f"contains wildcards: {', '.join(wildcards)}",
                    })
            except ClientError:
                pass
    except ClientError:
        pass

    return findings


def is_admin_policy(policy_arn: str) -> bool:
    """Check if a managed policy is an admin-level policy."""
    admin_arns = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
    }
    return policy_arn in admin_arns


def find_wildcards(policy_document: dict) -> list[str]:
    """Find wildcard (*) usages in a policy document.

    Flags any Action containing a "*" anywhere — a bare "*", a service-level
    wildcard ("s3:*"), and a partial-action wildcard ("s3:Get*") are all
    broader than a single explicit action and all worth a human's attention;
    a security audit tool should over-flag rather than silently let a
    lesser-but-still-broad wildcard slip through as "not really a wildcard".
    Effect is compared case-insensitively: AWS's own policy grammar only
    ever emits "Allow"/"Deny" exactly, but this tool also processes
    policy documents that never went through AWS's validation (e.g. drafts
    from policy_generator.py), so case is not a safe bypass to rely on.
    """
    wildcards = []
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        effect = stmt.get("Effect", "")
        if not isinstance(effect, str) or effect.lower() != "allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if isinstance(action, str) and "*" in action:
                wildcards.append(f"Action:{action}")
                break

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        for resource in resources:
            if resource == "*":
                wildcards.append("Resource:*")
                break

    return wildcards


# ---------------------------------------------------------------------------
# Logging & Notifications
# ---------------------------------------------------------------------------

def log_event_to_dynamodb(
    bucket_name, account_id, region, status, event_name,
    vulnerability_type="IAM Audit", severity="HIGH",
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
    resource, account_id, region, status, details="", severity="HIGH",
    nlp_summary="",
):
    if not DISCORD_WEBHOOK_URL:
        return

    color = 0xE74C3C if severity == "CRITICAL" else 0xF39C12

    fields = [
        {"name": "🔑 Resource", "value": f"`{resource}`", "inline": True},
        {"name": "🏢 Account", "value": f"`{account_id}`", "inline": True},
        {"name": "⚠️ Severity", "value": f"**{severity}**", "inline": True},
        {"name": "📝 Details", "value": details[:500], "inline": False},
    ]
    if nlp_summary:
        fields.append({"name": "🧠 AI Incident Summary", "value": nlp_summary[:1024], "inline": False})

    embed = {
        "title": "👤 CSPM — IAM Overpermissive Policy Detected",
        "color": color,
        "fields": fields,
        "footer": {"text": "Serverless CSPM • IAM Audit • NLG Engine v1.0"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    payload = json.dumps({"embeds": [embed]}).encode("utf-8")
    try:
        response = http.request("POST", DISCORD_WEBHOOK_URL, body=payload,
                                headers={"Content-Type": "application/json"})
        if response.status not in (200, 204):
            logger.warning("Discord returned %s", response.status)
    except Exception as exc:
        logger.error("Discord notification failed: %s", exc)
