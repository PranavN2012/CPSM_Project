"""
CIS / SOC 2 / PCI-DSS Compliance Framework Mapping
====================================================

Maps each CSPM vulnerability type to real compliance framework controls.
Used by the API Lambda and PDF report generator.
"""

# ---------------------------------------------------------------------------
# Framework Definitions
# ---------------------------------------------------------------------------

FRAMEWORKS = {
    "CIS AWS": {
        "name": "CIS Amazon Web Services Foundations Benchmark v2.0",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services",
    },
    "SOC 2": {
        "name": "SOC 2 Type II - Trust Services Criteria",
        "url": "https://www.aicpa.org/soc2",
    },
    "PCI-DSS": {
        "name": "PCI Data Security Standard v4.0",
        "url": "https://www.pcisecuritystandards.org/",
    },
}


# ---------------------------------------------------------------------------
# Control Mappings
# ---------------------------------------------------------------------------

COMPLIANCE_MAP = {
    "S3 Public Access": {
        "description": "S3 buckets must have public access block enabled to prevent unauthorized data exposure.",
        "controls": [
            {
                "framework": "CIS AWS",
                "control_id": "2.1.5",
                "title": "Ensure that S3 Buckets are configured with Block Public Access",
                "severity": "CRITICAL",
                "section": "Storage",
            },
            {
                "framework": "SOC 2",
                "control_id": "CC6.1",
                "title": "Logical and Physical Access Controls - Restrict data access to authorized users",
                "severity": "HIGH",
                "section": "Common Criteria",
            },
            {
                "framework": "PCI-DSS",
                "control_id": "2.2",
                "title": "Develop configuration standards for all system components",
                "severity": "HIGH",
                "section": "Build and Maintain a Secure Network",
            },
            {
                "framework": "PCI-DSS",
                "control_id": "7.1",
                "title": "Limit access to system components and cardholder data",
                "severity": "CRITICAL",
                "section": "Implement Strong Access Control Measures",
            },
        ],
    },
    "S3 Encryption": {
        "description": "S3 buckets must have default server-side encryption enabled to protect data at rest.",
        "controls": [
            {
                "framework": "CIS AWS",
                "control_id": "2.1.1",
                "title": "Ensure S3 Bucket Policy is set to deny HTTP requests (encryption in transit)",
                "severity": "HIGH",
                "section": "Storage",
            },
            {
                "framework": "CIS AWS",
                "control_id": "2.1.2",
                "title": "Ensure S3 bucket server-side encryption (SSE) is enabled",
                "severity": "HIGH",
                "section": "Storage",
            },
            {
                "framework": "SOC 2",
                "control_id": "CC6.1",
                "title": "Logical and Physical Access Controls - Encryption of data at rest",
                "severity": "HIGH",
                "section": "Common Criteria",
            },
            {
                "framework": "SOC 2",
                "control_id": "CC6.7",
                "title": "Restrict transmission, movement, and removal of data",
                "severity": "MEDIUM",
                "section": "Common Criteria",
            },
            {
                "framework": "PCI-DSS",
                "control_id": "3.4",
                "title": "Render PAN unreadable anywhere it is stored (encryption)",
                "severity": "CRITICAL",
                "section": "Protect Stored Account Data",
            },
        ],
    },
    "IAM Audit": {
        "description": "IAM policies must follow least-privilege principle. Wildcard permissions grant unrestricted access.",
        "controls": [
            {
                "framework": "CIS AWS",
                "control_id": "1.16",
                "title": "Ensure IAM policies that allow full *:* are not attached",
                "severity": "CRITICAL",
                "section": "Identity and Access Management",
            },
            {
                "framework": "CIS AWS",
                "control_id": "1.22",
                "title": "Ensure IAM policies granting full administrative privileges are not created",
                "severity": "CRITICAL",
                "section": "Identity and Access Management",
            },
            {
                "framework": "SOC 2",
                "control_id": "CC6.3",
                "title": "Role-based access and least-privilege principle",
                "severity": "HIGH",
                "section": "Common Criteria",
            },
            {
                "framework": "PCI-DSS",
                "control_id": "7.1",
                "title": "Limit access to system components to only those who require access",
                "severity": "CRITICAL",
                "section": "Implement Strong Access Control Measures",
            },
            {
                "framework": "PCI-DSS",
                "control_id": "7.2",
                "title": "Establish an access control model based on least privilege",
                "severity": "HIGH",
                "section": "Implement Strong Access Control Measures",
            },
        ],
    },
    "Security Group Open SSH": {
        "description": "Security Groups must not permit unrestricted SSH (port 22) ingress from 0.0.0.0/0.",
        "controls": [
            {
                "framework": "CIS AWS",
                "control_id": "5.2",
                "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                "severity": "CRITICAL",
                "section": "Networking",
            },
            {
                "framework": "SOC 2",
                "control_id": "CC6.6",
                "title": "Implement logical access security software, infrastructure, and architectures",
                "severity": "HIGH",
                "section": "Common Criteria",
            },
            {
                "framework": "PCI-DSS",
                "control_id": "1.3.2",
                "title": "Limit inbound Internet traffic to IP addresses within the DMZ",
                "severity": "CRITICAL",
                "section": "Build and Maintain a Secure Network",
            },
        ],
    },
    "DynamoDB Unencrypted": {
        "description": "DynamoDB tables must be encrypted using AWS KMS to protect data at rest.",
        "controls": [
            {
                "framework": "SOC 2",
                "control_id": "CC6.1",
                "title": "Logical and Physical Access Controls - Encryption of data at rest",
                "severity": "HIGH",
                "section": "Common Criteria",
            },
            {
                "framework": "PCI-DSS",
                "control_id": "3.4",
                "title": "Render PAN unreadable anywhere it is stored (encryption)",
                "severity": "HIGH",
                "section": "Protect Stored Account Data",
            },
        ],
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_compliance_for_event(event: dict) -> dict:
    """
    Given a CSPM event dict, return its compliance mapping.

    Returns:
        {
            "vulnerability_type": "S3 Public Access",
            "status": "PASS" | "FAIL",
            "frameworks": [ { framework, control_id, title, status } ]
        }
    """
    vuln_type = event.get("vulnerability_type", "S3 Public Access")
    status = event.get("status", "")

    is_compliant = status in ("COMPLIANT", "REMEDIATED", "ENCRYPTION_REMEDIATED")

    mapping = COMPLIANCE_MAP.get(vuln_type, {})
    controls = mapping.get("controls", [])

    return {
        "vulnerability_type": vuln_type,
        "description": mapping.get("description", ""),
        "status": "PASS" if is_compliant else "FAIL",
        "controls": [
            {
                "framework": c["framework"],
                "control_id": c["control_id"],
                "title": c["title"],
                "severity": c["severity"],
                "section": c["section"],
                "status": "PASS" if is_compliant else "FAIL",
            }
            for c in controls
        ],
    }


def get_compliance_summary(events: list[dict]) -> dict:
    """
    Compute aggregate compliance stats across all frameworks.

    Returns:
        {
            "overall_score": 87.5,
            "frameworks": { "CIS AWS": { "total": 5, "passed": 4, "score": 80.0 }, ... },
            "controls": [ ... all individual control results ... ]
        }
    """
    framework_stats = {}
    all_controls = []

    for event in events:
        result = get_compliance_for_event(event)
        for control in result["controls"]:
            fw = control["framework"]
            if fw not in framework_stats:
                framework_stats[fw] = {"total": 0, "passed": 0}
            framework_stats[fw]["total"] += 1
            if control["status"] == "PASS":
                framework_stats[fw]["passed"] += 1
            all_controls.append(control)

    # Compute per-framework scores
    for fw, stats in framework_stats.items():
        stats["score"] = round(
            (stats["passed"] / stats["total"] * 100) if stats["total"] > 0 else 0, 1
        )

    # Overall score
    total = sum(s["total"] for s in framework_stats.values())
    passed = sum(s["passed"] for s in framework_stats.values())
    overall = round((passed / total * 100) if total > 0 else 0, 1)

    return {
        "overall_score": overall,
        "frameworks": framework_stats,
        "controls_checked": total,
        "controls_passed": passed,
    }
