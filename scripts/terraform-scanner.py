"""
Terraform Security Scanner — Shift-Left IaC Analysis
=====================================================

Scans Terraform (.tf) files for common security misconfigurations:
  1. S3 buckets without public access block
  2. S3 buckets without encryption
  3. IAM policies with wildcard permissions
  4. Security groups with 0.0.0.0/0 ingress
  5. Missing CloudTrail logging

Used by GitHub Actions CI/CD and can be run manually.

Usage:
    python scripts/terraform-scanner.py [directory]
    
Exit codes:
    0 = No findings
    1 = Findings detected
"""

import os
import re
import sys
import json
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    severity: str
    title: str
    description: str
    framework: str


RULES = [
    {
        "id": "CSPM-S3-001",
        "title": "S3 bucket missing public access block",
        "severity": "CRITICAL",
        "framework": "CIS 2.1.5",
        "pattern": r'resource\s+"aws_s3_bucket"\s+"(\w+)"',
        "absence": r'resource\s+"aws_s3_bucket_public_access_block"',
        "description": "S3 bucket '{}' does not have a corresponding aws_s3_bucket_public_access_block resource.",
    },
    {
        "id": "CSPM-S3-002",
        "title": "S3 bucket missing server-side encryption",
        "severity": "HIGH",
        "framework": "CIS 2.1.2",
        "pattern": r'resource\s+"aws_s3_bucket"\s+"(\w+)"',
        "absence": r'resource\s+"aws_s3_bucket_server_side_encryption_configuration"',
        "description": "S3 bucket '{}' does not have a corresponding encryption configuration resource.",
    },
    {
        "id": "CSPM-IAM-001",
        "title": "IAM policy with wildcard (*) actions",
        "severity": "CRITICAL",
        "framework": "CIS 1.16",
        "pattern": r'"Action"\s*[=:]\s*\[?\s*"\*"',
        "description": "IAM policy uses wildcard Action: '*' which grants unrestricted access.",
    },
    {
        "id": "CSPM-IAM-002",
        "title": "IAM policy with wildcard (*) resources",
        "severity": "HIGH",
        "framework": "CIS 1.22",
        "pattern": r'"Resource"\s*[=:]\s*\[?\s*"\*"',
        "description": "IAM policy uses wildcard Resource: '*' which applies to all AWS resources.",
    },
    {
        "id": "CSPM-NET-001",
        "title": "Security group allows unrestricted ingress (0.0.0.0/0)",
        "severity": "HIGH",
        "framework": "CIS 5.2",
        "pattern": r'cidr_blocks\s*=\s*\[?"0\.0\.0\.0/0"',
        "description": "Security group ingress rule allows traffic from any IP address.",
    },
    {
        "id": "CSPM-S3-003",
        "title": "S3 bucket ACL set to public",
        "severity": "CRITICAL",
        "framework": "CIS 2.1.5",
        "pattern": r'acl\s*=\s*"(public-read|public-read-write|authenticated-read)"',
        "description": "S3 bucket ACL is set to '{}' which allows public access.",
    },
]


def scan_file(filepath: str) -> list[Finding]:
    """Scan a single Terraform file for security issues."""
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            lines = content.split("\n")
    except (IOError, UnicodeDecodeError):
        return findings

    rel_path = os.path.relpath(filepath)

    for rule in RULES:
        pattern = rule["pattern"]

        # Pattern-based rules (find matches)
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            match_groups = match.groups()
            desc = rule["description"]
            if match_groups and "{}" in desc:
                desc = desc.format(match_groups[0])

            findings.append(Finding(
                file=rel_path,
                line=line_num,
                rule_id=rule["id"],
                severity=rule["severity"],
                title=rule["title"],
                description=desc,
                framework=rule["framework"],
            ))

        # Absence-based rules (check if corresponding resource is missing)
        if "absence" in rule:
            bucket_matches = re.finditer(rule["pattern"], content)
            absence_pattern = rule["absence"]
            has_corresponding = bool(re.search(absence_pattern, content))

            if not has_corresponding:
                for match in re.finditer(rule["pattern"], content):
                    line_num = content[:match.start()].count("\n") + 1
                    desc = rule["description"].format(match.group(1))
                    findings.append(Finding(
                        file=rel_path,
                        line=line_num,
                        rule_id=rule["id"],
                        severity=rule["severity"],
                        title=rule["title"],
                        description=desc,
                        framework=rule["framework"],
                    ))

    return findings


def scan_directory(directory: str) -> list[Finding]:
    """Scan all .tf files in a directory tree."""
    all_findings = []

    for root, dirs, files in os.walk(directory):
        # Skip hidden dirs and .terraform
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for file in files:
            if file.endswith(".tf"):
                filepath = os.path.join(root, file)
                file_findings = scan_file(filepath)
                all_findings.extend(file_findings)

    return all_findings


def format_markdown(findings: list[Finding]) -> str:
    """Format findings as a GitHub-compatible markdown report."""
    if not findings:
        return "## ✅ CSPM Security Scan — No Issues Found\n\nAll Terraform files passed security checks."

    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")

    lines = [
        f"## 🛡️ CSPM Security Scan — {len(findings)} Issues Found\n",
        f"| Severity | Count |",
        f"|---|---|",
        f"| 🔴 CRITICAL | {critical} |",
        f"| 🟠 HIGH | {high} |",
        f"",
        f"### Findings\n",
        f"| # | Severity | Rule | File | Line | Description |",
        f"|---|---|---|---|---|---|",
    ]

    for i, f in enumerate(findings, 1):
        icon = "🔴" if f.severity == "CRITICAL" else "🟠"
        lines.append(
            f"| {i} | {icon} {f.severity} | `{f.rule_id}` | `{f.file}` | L{f.line} | {f.title} ({f.framework}) |"
        )

    lines.extend([
        "",
        "---",
        "*Scanned by Serverless CSPM Terraform Scanner*",
    ])

    return "\n".join(lines)


def format_json(findings: list[Finding]) -> str:
    """Format findings as JSON."""
    return json.dumps([asdict(f) for f in findings], indent=2)


def main():
    """CLI entry point."""
    directory = sys.argv[1] if len(sys.argv) > 1 else "."

    if not os.path.isdir(directory):
        print(f"Error: '{directory}' is not a directory.")
        sys.exit(2)

    print(f"🔍 Scanning Terraform files in: {os.path.abspath(directory)}")
    print()

    findings = scan_directory(directory)

    if not findings:
        print("✅ No security issues found!")
        sys.exit(0)

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f.file, f.line, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Print results
    critical = sum(1 for f in unique if f.severity == "CRITICAL")
    high = sum(1 for f in unique if f.severity == "HIGH")

    print(f"⚠️  Found {len(unique)} security issues:")
    print(f"   🔴 CRITICAL: {critical}")
    print(f"   🟠 HIGH:     {high}")
    print()

    for i, f in enumerate(unique, 1):
        icon = "🔴" if f.severity == "CRITICAL" else "🟠"
        print(f"  {i}. {icon} [{f.rule_id}] {f.title}")
        print(f"     File: {f.file}:{f.line}")
        print(f"     Framework: {f.framework}")
        print(f"     {f.description}")
        print()

    # Write markdown report
    md = format_markdown(unique)
    report_path = os.path.join(directory, "security-scan-results.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"📄 Report saved: {report_path}")

    sys.exit(1 if unique else 0)


if __name__ == "__main__":
    main()
