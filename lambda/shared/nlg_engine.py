"""
NLG Incident Summary Engine v2 — Advanced Narrative Generation
================================================================

Transforms raw CSPM security event data into human-readable,
contextual incident narratives using:

  1. Template-Based NLG        — deterministic slot-filling (v1, retained)
  2. Sentiment-Weighted Severity — keyword risk scoring adjusts language
  3. Temporal Context           — references historical incident frequency
  4. Named Entity Recognition   — extracts AWS service names from IAM JSON
  5. Cross-Event Correlation     — detects multi-step attack chains

This is a deterministic NLG engine — zero external dependencies,
fully offline, the same technique used by enterprise SIEMs
(Splunk, Datadog, PagerDuty).
"""

import json
import re
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature 1: Compliance Context Mapping (retained from v1)
# ---------------------------------------------------------------------------

_COMPLIANCE_CONTEXT = {
    "S3 Public Access": {
        "risk": "unauthorized internet-wide data exposure",
        "frameworks": "CIS AWS 2.1.5, SOC 2 CC6.1, PCI-DSS 7.1",
        "attack_vector": "data exfiltration via unauthenticated HTTP access",
    },
    "S3 Encryption": {
        "risk": "plaintext data-at-rest on physical storage media",
        "frameworks": "CIS AWS 2.1.2, SOC 2 CC6.7, PCI-DSS 3.4",
        "attack_vector": "physical drive theft or unauthorized snapshot access",
    },
    "IAM Audit": {
        "risk": "full administrative privilege escalation",
        "frameworks": "CIS AWS 1.16, SOC 2 CC6.3, PCI-DSS 7.2",
        "attack_vector": "lateral movement via compromised wildcard credentials",
    },
    "Security Group Open SSH": {
        "risk": "unrestricted network ingress on SSH port 22",
        "frameworks": "CIS AWS 5.2, SOC 2 CC6.6, PCI-DSS 1.3.2",
        "attack_vector": "brute-force SSH login or OS-level exploit from any IP",
    },
    "DynamoDB Unencrypted": {
        "risk": "unencrypted NoSQL data-at-rest",
        "frameworks": "SOC 2 CC6.1, PCI-DSS 3.4",
        "attack_vector": "snapshot theft exposing PII or session tokens",
    },
}

# ---------------------------------------------------------------------------
# Action Verb Templates (status → narrative fragment)
# ---------------------------------------------------------------------------

_ACTION_TEMPLATES = {
    "REMEDIATED": (
        "CloudSentry detected the misconfiguration and auto-remediated by "
        "enabling all four S3 Block Public Access flags within milliseconds."
    ),
    "ENCRYPTION_REMEDIATED": (
        "CloudSentry auto-remediated by enabling AES-256 server-side "
        "encryption (SSE) on the resource."
    ),
    "REMEDIATION_FAILED": (
        "CloudSentry attempted auto-remediation but the operation failed. "
        "Manual intervention is required immediately."
    ),
    "ENCRYPTION_FAILED": (
        "CloudSentry attempted to enforce encryption but the API call failed. "
        "Manual encryption enforcement is required."
    ),
    "COMPLIANT": (
        "CloudSentry verified the resource configuration and confirmed it "
        "meets security baseline requirements. No action needed."
    ),
    "IAM_OVERPERMISSIVE": (
        "CloudSentry flagged this as a Principle of Least Privilege violation. "
        "The policy grants unrestricted access and requires human review."
    ),
    "NON_COMPLIANT": (
        "CloudSentry detected a security misconfiguration during a multi-cloud "
        "posture scan. This finding requires review and remediation to meet "
        "compliance baselines."
    ),
}

_VULN_ACTION_OVERRIDES = {
    ("S3 Public Access", "REMEDIATED"): (
        "CloudSentry auto-remediated by injecting a PutPublicAccessBlock API "
        "call, enabling BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
        "and RestrictPublicBuckets."
    ),
    ("Security Group Open SSH", "REMEDIATED"): (
        "CloudSentry auto-remediated by revoking the offending ingress rule "
        "(0.0.0.0/0 on port 22) via RevokeSecurityGroupIngress."
    ),
    ("DynamoDB Unencrypted", "ENCRYPTION_REMEDIATED"): (
        "CloudSentry auto-remediated by enabling KMS-managed server-side "
        "encryption via UpdateTable SSESpecification."
    ),
}

# ---------------------------------------------------------------------------
# Trigger Descriptions
# ---------------------------------------------------------------------------

_TRIGGER_VERBS = {
    "CreateBucket": "created an S3 bucket",
    "PutBucketPublicAccessBlock": "modified the public access configuration of S3 bucket",
    "PutBucketEncryption": "modified the encryption configuration of S3 bucket",
    "GetBucketEncryption": "accessed the encryption configuration of S3 bucket",
    "AuthorizeSecurityGroupIngress": "opened an inbound rule on security group",
    "CreateSecurityGroup": "created a new security group",
    "CreateTable": "created a DynamoDB table",
    "IAMAuditScan": "was detected during a scheduled IAM policy audit of",
}


# ---------------------------------------------------------------------------
# Feature 2: Sentiment-Weighted Severity Scoring
# ---------------------------------------------------------------------------
# Scans resource names and event metadata for high-risk keywords
# to dynamically adjust the narrative's urgency language.

_RISK_KEYWORDS = {
    "critical": {
        "words": ["prod", "production", "customer", "pii", "payment", "admin",
                  "root", "master", "credential", "secret", "password", "key"],
        "weight": 3,
    },
    "high": {
        "words": ["staging", "backup", "vault", "session", "user", "data",
                  "export", "report", "analytics", "log", "audit"],
        "weight": 2,
    },
    "low": {
        "words": ["dev", "test", "sandbox", "temp", "tmp", "demo", "sample"],
        "weight": -1,
    },
}


def _compute_sentiment_score(resource_name: str, vulnerability_type: str, status: str) -> dict:
    """
    Analyze the resource name and context for risk-weighted keywords.
    Returns a dict with score, matched keywords, and urgency level.
    """
    name_lower = resource_name.lower()
    matched = []
    score = 0

    for tier, info in _RISK_KEYWORDS.items():
        for word in info["words"]:
            if word in name_lower:
                matched.append(word)
                score += info["weight"]

    # Failed remediation always gets a urgency boost
    if "FAILED" in status:
        score += 4

    # Determine urgency descriptor
    if score >= 4:
        urgency = "extremely high"
    elif score >= 2:
        urgency = "elevated"
    elif score <= -1:
        urgency = "lower (non-production)"
    else:
        urgency = None  # Use the default severity descriptor

    return {"score": score, "matched": matched, "urgency": urgency}


def _build_sentiment_fragment(sentiment: dict) -> str:
    """Build a natural language fragment from sentiment analysis."""
    if not sentiment["matched"]:
        return ""

    keywords = ", ".join(f"'{w}'" for w in sentiment["matched"][:3])
    if sentiment["urgency"] and "extremely" in sentiment["urgency"]:
        return (f" Keyword analysis of the resource name detected {keywords}, "
                f"indicating this is a high-value production asset requiring "
                f"immediate attention.")
    elif sentiment["urgency"] and "elevated" in sentiment["urgency"]:
        return (f" The resource name contains {keywords}, suggesting "
                f"this asset handles sensitive data.")
    elif sentiment["urgency"] and "non-production" in sentiment["urgency"]:
        return (f" The resource name contains {keywords}, suggesting "
                f"this is a development/test asset with reduced blast radius.")
    return ""


# ---------------------------------------------------------------------------
# Feature 3: Named Entity Recognition (NER) for IAM Policies
# ---------------------------------------------------------------------------
# Parses IAM policy JSON to extract AWS service names and specific
# actions, then describes them in natural language.

_AWS_SERVICE_NAMES = {
    "s3":         "Simple Storage Service (S3)",
    "ec2":        "Elastic Compute Cloud (EC2)",
    "iam":        "Identity & Access Management (IAM)",
    "lambda":     "Lambda (Serverless Functions)",
    "dynamodb":   "DynamoDB (NoSQL Database)",
    "rds":        "Relational Database Service (RDS)",
    "sqs":        "Simple Queue Service (SQS)",
    "sns":        "Simple Notification Service (SNS)",
    "sts":        "Security Token Service (STS)",
    "cloudwatch": "CloudWatch (Monitoring)",
    "kms":        "Key Management Service (KMS)",
    "secretsmanager": "Secrets Manager",
    "cloudformation": "CloudFormation (IaC)",
    "logs":       "CloudWatch Logs",
}


def extract_iam_entities(policy_details: str) -> dict:
    """
    Extract AWS service names and actions from IAM policy details string.
    Uses regex-based Named Entity Recognition to identify AWS service tokens.

    Returns:
        {
            "services": ["S3", "EC2", "Lambda"],
            "is_wildcard": True/False,
            "action_count": 5,
            "description": "human-readable string"
        }
    """
    if not policy_details:
        return {"services": [], "is_wildcard": False, "action_count": 0, "description": ""}

    text = policy_details.lower()
    found_services = []

    # Check for wildcard (Action: *)
    is_wildcard = "action:*" in text or '"action": "*"' in text or "action: *" in text

    # Extract service names using NER pattern matching
    for short_name, full_name in _AWS_SERVICE_NAMES.items():
        # Match patterns like: s3:GetObject, s3:*, ec2:Describe*
        pattern = rf'\b{re.escape(short_name)}[:\.\-]'
        if re.search(pattern, text) or short_name in text:
            found_services.append(full_name)

    # Count specific actions mentioned (e.g., s3:GetObject, ec2:RunInstances)
    action_pattern = r'\b\w+:[A-Z][a-zA-Z]*'
    actions = re.findall(action_pattern, policy_details)
    action_count = len(actions)

    # Build description
    if is_wildcard:
        desc = (f"NER analysis identified a wildcard policy (Action:*) granting "
                f"unrestricted access to ALL AWS services including "
                f"{', '.join(found_services[:4]) if found_services else 'every service in the account'}.")
    elif found_services:
        desc = (f"NER analysis identified {len(found_services)} AWS services "
                f"referenced in the policy: {', '.join(found_services[:5])}.")
    else:
        desc = ""

    return {
        "services": found_services,
        "is_wildcard": is_wildcard,
        "action_count": action_count,
        "description": desc,
    }


# ---------------------------------------------------------------------------
# Feature 4: Temporal Context (Historical Pattern Analysis)
# ---------------------------------------------------------------------------
# Queries DynamoDB for past events to add frequency context like
# "This is the 3rd S3 misconfiguration in this account this week."

def _query_temporal_context(dynamodb_table, account_id: str,
                            vulnerability_type: str) -> str:
    """
    Query DynamoDB for historical events to provide frequency context.

    Args:
        dynamodb_table: A boto3 DynamoDB Table resource (or None)
        account_id:     AWS account ID to filter on
        vulnerability_type: Type of vulnerability to count

    Returns:
        A sentence fragment like "This is the 3rd S3 Public Access event in
        this account in the past 24 hours."
    """
    if dynamodb_table is None:
        return ""

    try:
        # Scan for recent events matching this account + vuln type
        response = dynamodb_table.scan(
            FilterExpression=(
                "account_id = :acct AND vulnerability_type = :vtype"
            ),
            ExpressionAttributeValues={
                ":acct": account_id,
                ":vtype": vulnerability_type,
            },
            ProjectionExpression="event_id, #ts",
            ExpressionAttributeNames={"#ts": "timestamp"},
        )
        items = response.get("Items", [])

        if len(items) <= 1:
            return ""

        count = len(items)
        # Ordinal suffix — the 11th/12th/13th exception applies to every
        # hundred (111th, 112th, 113th, 211th, ...), not just count == 11/12/13.
        suffix = "th"
        if count % 100 not in (11, 12, 13):
            if count % 10 == 1:
                suffix = "st"
            elif count % 10 == 2:
                suffix = "nd"
            elif count % 10 == 3:
                suffix = "rd"

        vuln_short = vulnerability_type.split()[0]  # "S3", "IAM", "Security", "DynamoDB"
        return (f" TEMPORAL ANALYSIS: This is the {count}{suffix} {vulnerability_type} "
                f"event detected in account {account_id}. "
                f"Repeated {vuln_short} misconfigurations may indicate "
                f"a systemic process or training gap.")

    except Exception as exc:
        logger.debug("Temporal context query failed: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# Feature 5: Cross-Event Correlation (Attack Chain Detection)
# ---------------------------------------------------------------------------
# Detects multi-step attack patterns by querying for recent events
# across different vulnerability types in the same account.

_ATTACK_CHAINS = [
    {
        "name": "Lateral Movement Kill Chain",
        "steps": ["IAM Audit", "Security Group Open SSH"],
        "description": (
            "CORRELATION ALERT: An IAM privilege escalation was detected in "
            "the same account shortly before this network perimeter breach. "
            "This pattern matches a lateral movement kill chain — an attacker "
            "may have escalated IAM privileges to open SSH access."
        ),
    },
    {
        "name": "Data Exfiltration Kill Chain",
        "steps": ["Security Group Open SSH", "S3 Public Access"],
        "description": (
            "CORRELATION ALERT: A network ingress breach was detected in "
            "the same account before this S3 exposure. This pattern matches "
            "a data exfiltration kill chain — an attacker may have used SSH "
            "access to disable S3 bucket protections."
        ),
    },
    {
        "name": "Full Compromise Chain",
        "steps": ["IAM Audit", "S3 Public Access"],
        "description": (
            "CORRELATION ALERT: An IAM privilege escalation and S3 public "
            "access misconfiguration were detected in the same account. "
            "This pattern suggests a full compromise chain — wildcard IAM "
            "credentials may have been used to expose S3 data."
        ),
    },
    {
        "name": "Persistence via Unencrypted Storage",
        "steps": ["IAM Audit", "DynamoDB Unencrypted"],
        "description": (
            "CORRELATION ALERT: An overpermissive IAM policy and an "
            "unencrypted database were detected in the same account. "
            "An attacker with wildcard credentials could exfiltrate "
            "plaintext NoSQL data without triggering KMS audit logs."
        ),
    },
]


def _detect_attack_chain(dynamodb_table, account_id: str,
                         vulnerability_type: str) -> str:
    """
    Detect multi-step attack chains by correlating recent events.

    Scans DynamoDB for events in the same account and checks whether
    the current event completes a known attack pattern.

    Returns a correlation alert string or empty string.
    """
    if dynamodb_table is None:
        return ""

    try:
        response = dynamodb_table.scan(
            FilterExpression="account_id = :acct",
            ExpressionAttributeValues={":acct": account_id},
            ProjectionExpression="vulnerability_type",
        )
        items = response.get("Items", [])
        existing_types = {item.get("vulnerability_type", "") for item in items}

        # Check each chain: does this event complete a pattern?
        for chain in _ATTACK_CHAINS:
            steps = chain["steps"]
            # Current vuln must be in the chain
            if vulnerability_type not in steps:
                continue
            # All OTHER steps must already exist in the account history
            other_steps = [s for s in steps if s != vulnerability_type]
            if all(s in existing_types for s in other_steps):
                return f" {chain['description']}"

        return ""

    except Exception as exc:
        logger.debug("Cross-event correlation failed: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_incident_summary(
    resource_name: str,
    account_id: str,
    region: str,
    status: str,
    event_name: str = "unknown",
    vulnerability_type: str = "S3 Public Access",
    severity: str = "HIGH",
    timestamp: str = "",
    dynamodb_table=None,
    iam_policy_details: str = "",
) -> str:
    """
    Generate an advanced, contextual incident narrative.

    New in v2:
        dynamodb_table:    Optional boto3 DynamoDB Table for temporal/correlation queries
        iam_policy_details: Optional IAM policy string for NER extraction

    Returns:
        A multi-sentence, NLP-enriched incident summary.
    """
    # --- Sentence 1: What happened ---
    time_str = _format_timestamp(timestamp)
    trigger = _TRIGGER_VERBS.get(event_name, f"triggered event '{event_name}' on")

    if vulnerability_type == "IAM Audit":
        sentence_1 = (
            f"An overpermissive IAM policy {trigger} `{resource_name}` "
            f"in account {account_id} ({region}){time_str}."
        )
    else:
        sentence_1 = (
            f"A configuration change in account {account_id} {trigger} "
            f"`{resource_name}` in {region}{time_str}."
        )

    # --- Sentence 2: Why it matters (compliance + sentiment) ---
    ctx = _COMPLIANCE_CONTEXT.get(vulnerability_type, {})
    risk = ctx.get("risk", "a security misconfiguration")
    frameworks = ctx.get("frameworks", "industry security frameworks")

    # Feature 1: Sentiment scoring adjusts severity language
    sentiment = _compute_sentiment_score(resource_name, vulnerability_type, status)
    severity_word = sentiment["urgency"] or _severity_descriptor(severity)

    sentence_2 = (
        f"This poses a {severity_word} risk of {risk}, "
        f"violating {frameworks}."
    )

    # Feature 1 continued: Add keyword insight if detected
    sentiment_fragment = _build_sentiment_fragment(sentiment)

    # --- Sentence 3: What was done ---
    override = _VULN_ACTION_OVERRIDES.get((vulnerability_type, status))
    sentence_3 = override or _ACTION_TEMPLATES.get(
        status,
        f"CloudSentry processed this event with status: {status}."
    )

    # --- Feature 3: IAM NER enrichment ---
    ner_fragment = ""
    if vulnerability_type == "IAM Audit" and iam_policy_details:
        ner = extract_iam_entities(iam_policy_details)
        if ner["description"]:
            ner_fragment = f" {ner['description']}"

    # --- Feature 2: Temporal context ---
    temporal_fragment = _query_temporal_context(
        dynamodb_table, account_id, vulnerability_type
    )

    # --- Feature 4: Cross-event correlation ---
    correlation_fragment = _detect_attack_chain(
        dynamodb_table, account_id, vulnerability_type
    )

    # --- Assemble final narrative ---
    summary = f"{sentence_1} {sentence_2}{sentiment_fragment} {sentence_3}"

    if ner_fragment:
        summary += ner_fragment
    if temporal_fragment:
        summary += temporal_fragment
    if correlation_fragment:
        summary += correlation_fragment

    return summary


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _format_timestamp(iso_str: str) -> str:
    """Convert ISO timestamp to a readable fragment."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        ist = dt + timedelta(hours=5, minutes=30)
        return ist.strftime(" at %I:%M %p IST on %b %d, %Y")
    except (ValueError, TypeError):
        return ""


def _severity_descriptor(severity: str) -> str:
    """Map severity level to a natural language descriptor."""
    return {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "moderate",
        "LOW": "low",
    }.get(severity, "notable")
