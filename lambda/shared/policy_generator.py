"""
Policy Auto-Generator — Self-Learning from Incidents
=======================================================

When the remediation Lambda encounters a vulnerability type that
doesn't match any existing policy, this module auto-creates a
YAML policy stub and flags it for human review.

Architecture: Pattern detection → YAML stub → "Pending Review" in UI.
"""

import os
import glob
import logging
from datetime import datetime, timezone

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.normpath(os.path.join(_SCRIPT_DIR, "..", ".."))
_POLICIES_DIR = os.path.join(_PROJECT_DIR, "policies")

# ---------------------------------------------------------------------------
# Known vulnerability patterns → policy template mapping
# ---------------------------------------------------------------------------

VULNERABILITY_PATTERNS = {
    # S3 patterns
    "s3_public":        {"service": "s3",         "severity": "CRITICAL", "check": "check_s3_public_access"},
    "s3_encryption":    {"service": "s3",         "severity": "HIGH",     "check": "check_s3_encryption"},
    "s3_versioning":    {"service": "s3",         "severity": "MEDIUM",   "check": "check_s3_versioning"},
    "s3_logging":       {"service": "s3",         "severity": "MEDIUM",   "check": "check_s3_logging"},

    # IAM patterns
    "iam_admin":        {"service": "iam",        "severity": "CRITICAL", "check": "check_iam_admin"},
    "iam_wildcard":     {"service": "iam",        "severity": "CRITICAL", "check": "check_iam_wildcard"},
    "iam_mfa":          {"service": "iam",        "severity": "HIGH",     "check": "check_iam_mfa"},
    "iam_unused":       {"service": "iam",        "severity": "MEDIUM",   "check": "check_iam_unused_creds"},

    # EC2 patterns
    "sg_ssh":           {"service": "ec2",        "severity": "HIGH",     "check": "check_sg_ssh"},
    "sg_rdp":           {"service": "ec2",        "severity": "HIGH",     "check": "check_sg_rdp"},
    "sg_open":          {"service": "ec2",        "severity": "HIGH",     "check": "check_sg_open_ports"},
    "ebs_encryption":   {"service": "ec2",        "severity": "HIGH",     "check": "check_ebs_encryption"},

    # DynamoDB patterns
    "dynamodb_encrypt": {"service": "dynamodb",   "severity": "MEDIUM",   "check": "check_dynamodb_encryption"},

    # RDS patterns
    "rds_public":       {"service": "rds",        "severity": "CRITICAL", "check": "check_rds_public"},
    "rds_encryption":   {"service": "rds",        "severity": "HIGH",     "check": "check_rds_encryption"},

    # Lambda patterns
    "lambda_public":    {"service": "lambda",     "severity": "HIGH",     "check": "check_lambda_public_url"},

    # CloudTrail patterns
    "cloudtrail":       {"service": "cloudtrail", "severity": "HIGH",     "check": "check_cloudtrail_enabled"},
}

# Keywords to detect provider from event
PROVIDER_KEYWORDS = {
    "aws": ["s3", "ec2", "iam", "dynamodb", "rds", "lambda", "cloudtrail", "sqs", "sns"],
    "azure": ["blob", "nsg", "vnet", "rbac", "keyvault", "cosmos"],
    "gcp": ["gcs", "gce", "gke", "bigquery", "cloudsql", "firewall"],
}


# ---------------------------------------------------------------------------
# Core Logic
# ---------------------------------------------------------------------------

def _detect_provider(event: dict) -> str:
    """Detect cloud provider from event data."""
    # Check explicit provider field
    if "provider" in event:
        return event["provider"].lower()

    # Check source/service fields for provider keywords
    source = str(event.get("source", "")).lower()
    service = str(event.get("service", "")).lower()
    resource = str(event.get("resource_id", "")).lower()
    combined = f"{source} {service} {resource}"

    for provider, keywords in PROVIDER_KEYWORDS.items():
        for kw in keywords:
            if kw in combined:
                return provider

    return "aws"  # Default to AWS


def _detect_vulnerability_type(event: dict) -> tuple[str, dict]:
    """Detect vulnerability type from event and return (type_key, pattern_info).

    Returns ("unknown", {}) if no pattern matches.
    """
    event_type = str(event.get("event_type", "")).lower()
    source = str(event.get("source", "")).lower()
    detail = str(event.get("detail", "")).lower()
    combined = f"{event_type} {source} {detail}"

    for pattern_key, pattern_info in VULNERABILITY_PATTERNS.items():
        # Check if pattern key terms appear in event
        terms = pattern_key.replace("_", " ").split()
        if all(term in combined for term in terms):
            return pattern_key, pattern_info

    return "unknown", {}


def _get_existing_policy_checks() -> set:
    """Get set of all check function names from existing policies."""
    checks = set()
    for filepath in glob.glob(os.path.join(_POLICIES_DIR, "*.yaml")):
        try:
            if _HAS_YAML:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            else:
                data = {}
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip().startswith("check:"):
                            data["check"] = line.split(":", 1)[1].strip().strip('"').strip("'")
                            break

            if data.get("check"):
                checks.add(data["check"])
        except Exception:
            continue
    return checks


def auto_generate_policy(event: dict) -> dict | None:
    """Auto-generate a YAML policy stub from an incident event.

    Returns the new policy dict if created, None if a matching policy exists.

    The generated policy has:
      - enabled: false (requires human review)
      - auto_generated: true
      - needs_review: true
    """
    vuln_type, pattern_info = _detect_vulnerability_type(event)
    provider = _detect_provider(event)

    if vuln_type == "unknown":
        # Create a generic stub
        event_type = event.get("event_type", "unknown_event")
        service = event.get("service", "unknown")
        policy_id = f"auto-{provider}-{service}-{event_type}".lower().replace(" ", "-")
        check_name = f"auto_check_{service}_{event_type}".lower().replace(" ", "_")
        severity = "MEDIUM"
        description = f"Auto-generated policy from detected incident: {event_type}"
    else:
        service = pattern_info.get("service", "unknown")
        check_name = pattern_info.get("check", "")
        severity = pattern_info.get("severity", "MEDIUM")
        policy_id = f"auto-{provider}-{vuln_type}".replace("_", "-")
        description = f"Auto-generated from {vuln_type.replace('_', ' ')} incident"

    # Check if policy or check already exists
    existing_checks = _get_existing_policy_checks()
    if check_name in existing_checks:
        logger.info("Policy for check '%s' already exists, skipping.", check_name)
        return None

    # Check by ID
    for filepath in glob.glob(os.path.join(_POLICIES_DIR, "*.yaml")):
        try:
            if _HAS_YAML:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            else:
                data = {}
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip().startswith("id:"):
                            data["id"] = line.split(":", 1)[1].strip().strip('"').strip("'")
                            break
            if data.get("id") == policy_id:
                return None
        except Exception:
            continue

    # Build policy stub
    policy = {
        "id": policy_id,
        "name": f"{service.upper()} {vuln_type.replace('_', ' ').title()}" if vuln_type != "unknown" else f"Incident: {event.get('event_type', 'unknown')}",
        "provider": provider,
        "service": service,
        "severity": severity,
        "description": description,
        "enabled": False,  # Requires review!
        "check": check_name,
        "remediation": "",
        "auto_remediate": False,
        "auto_generated": True,
        "needs_review": True,
        "generated_from": {
            "event_type": event.get("event_type", ""),
            "resource": event.get("resource_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "compliance": [
            {"framework": "Custom", "control": "Auto-detected"}
        ],
    }

    # Save to disk
    filename = f"{policy_id}.yaml"
    filepath = os.path.join(_POLICIES_DIR, filename)

    try:
        if _HAS_YAML:
            with open(filepath, "w", encoding="utf-8") as f:
                yaml.dump(policy, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        else:
            with open(filepath, "w", encoding="utf-8") as f:
                for key, val in policy.items():
                    if isinstance(val, dict):
                        f.write(f"{key}:\n")
                        for ik, iv in val.items():
                            f.write(f"  {ik}: \"{iv}\"\n")
                    elif isinstance(val, list):
                        f.write(f"{key}:\n")
                        for item in val:
                            if isinstance(item, dict):
                                first = True
                                for ik, iv in item.items():
                                    prefix = "  - " if first else "    "
                                    f.write(f'{prefix}{ik}: "{iv}"\n')
                                    first = False
                    elif isinstance(val, bool):
                        f.write(f"{key}: {'true' if val else 'false'}\n")
                    else:
                        f.write(f'{key}: "{val}"\n')

        logger.info("Auto-generated policy: %s → %s", policy_id, filepath)
        return policy

    except Exception as exc:
        logger.error("Failed to save auto-generated policy: %s", exc)
        return None


def get_pending_review_policies() -> list[dict]:
    """Get all policies that need human review."""
    pending = []
    for filepath in glob.glob(os.path.join(_POLICIES_DIR, "*.yaml")):
        try:
            if _HAS_YAML:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            else:
                continue

            if data.get("needs_review") or data.get("auto_generated"):
                pending.append(data)
        except Exception:
            continue
    return pending
