"""
Policy Feed Subscription — Multi-Source Policy Sync Engine
============================================================

Fetches security policies from 3 sources and converts to CloudSentry YAML:
  1. GitHub Community Repos — raw YAML files
  2. CIS Benchmarks — bundled baseline controls
  3. Prowler Open-Source — JSON metadata → YAML conversion

Architecture: Like antivirus signature updates for cloud security.
"""

import os
import json
import glob
import logging
import hashlib
from datetime import datetime, timezone

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

try:
    import urllib.request
    import urllib.error
    _HAS_HTTP = True
except ImportError:
    _HAS_HTTP = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.normpath(os.path.join(_SCRIPT_DIR, "..", ".."))
_POLICIES_DIR = os.path.join(_PROJECT_DIR, "policies")
_FEEDS_DIR = os.path.join(_POLICIES_DIR, "feeds")
_CIS_BASELINE = os.path.join(_FEEDS_DIR, "cis_baseline.json")

# Default GitHub community repo
DEFAULT_GITHUB_REPO = "PranavN2012/CPSM_Project"
DEFAULT_GITHUB_BRANCH = "main"
DEFAULT_GITHUB_PATH = "serverless-cspm/policies"

# Prowler GitHub raw base
PROWLER_RAW_BASE = "https://raw.githubusercontent.com/prowler-cloud/prowler/master"
PROWLER_CHECKS = {
    "aws": [
        ("s3", "s3_bucket_public_access", "S3 Bucket Public Access"),
        ("s3", "s3_bucket_server_side_encryption", "S3 Bucket Server-Side Encryption"),
        ("s3", "s3_bucket_versioning", "S3 Bucket Versioning"),
        ("ec2", "ec2_securitygroup_allow_ingress_from_internet_to_port_22", "SG Open SSH"),
        ("ec2", "ec2_securitygroup_allow_ingress_from_internet_to_port_3389", "SG Open RDP"),
        ("iam", "iam_root_access_key", "Root Access Key"),
        ("iam", "iam_root_mfa_enabled", "Root MFA Enabled"),
        ("iam", "iam_user_mfa_enabled_console_access", "IAM User MFA"),
        ("rds", "rds_instance_storage_encrypted", "RDS Storage Encryption"),
        ("cloudtrail", "cloudtrail_multi_region_enabled", "CloudTrail Multi-Region"),
        ("dynamodb", "dynamodb_table_encryption_at_rest", "DynamoDB Encryption"),
        ("lambda_", "lambda_function_url_public", "Lambda Public URL"),
    ],
    "azure": [
        ("storage", "storage_account_https_only", "Storage HTTPS Only"),
        ("storage", "storage_blob_public_access_level_disabled", "Blob Public Access"),
        ("network", "nsg_rdp_from_internet", "NSG RDP Open"),
    ],
    "gcp": [
        ("storage", "gcs_bucket_public_access", "GCS Public Access"),
        ("compute", "compute_firewall_allow_ingress_from_internet_to_port_22", "Firewall SSH Open"),
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch_url(url: str, timeout: int = 10) -> str | None:
    """Fetch content from a URL."""
    if not _HAS_HTTP:
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CloudSentry-PolicySync/3.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return None


def _policy_exists(policy_id: str) -> bool:
    """Check if a policy YAML with this ID already exists."""
    for filepath in glob.glob(os.path.join(_POLICIES_DIR, "*.yaml")):
        try:
            if _HAS_YAML:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            else:
                data = {}
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("id:"):
                            data["id"] = line.split(":", 1)[1].strip().strip('"').strip("'")
                            break
            if data.get("id") == policy_id:
                return True
        except Exception:
            continue
    return False


def _save_policy_yaml(policy: dict) -> str | None:
    """Save a policy dict as a YAML file. Returns filepath or None."""
    policy_id = policy.get("id", "unknown")
    filename = f"{policy_id.replace('.', '-').replace('_', '-')}.yaml"
    filepath = os.path.join(_POLICIES_DIR, filename)

    if os.path.exists(filepath):
        return None  # Already exists

    try:
        if _HAS_YAML:
            with open(filepath, "w", encoding="utf-8") as f:
                yaml.dump(policy, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        else:
            with open(filepath, "w", encoding="utf-8") as f:
                for key, val in policy.items():
                    if isinstance(val, list):
                        f.write(f"{key}:\n")
                        for item in val:
                            if isinstance(item, dict):
                                first = True
                                for ik, iv in item.items():
                                    prefix = "  - " if first else "    "
                                    f.write(f'{prefix}{ik}: "{iv}"\n')
                                    first = False
                            else:
                                f.write(f"  - {item}\n")
                    elif isinstance(val, bool):
                        f.write(f"{key}: {'true' if val else 'false'}\n")
                    else:
                        f.write(f'{key}: "{val}"\n')

        logger.info("Saved new policy: %s → %s", policy_id, filepath)
        return filepath
    except Exception as exc:
        logger.error("Failed to save policy %s: %s", policy_id, exc)
        return None


# ---------------------------------------------------------------------------
# Source 1: GitHub Community Repo
# ---------------------------------------------------------------------------

def sync_from_github(
    repo: str = None,
    branch: str = None,
    path: str = None,
) -> dict:
    """Fetch YAML policy files from a GitHub repository.

    Returns: {"source": "github", "added": int, "skipped": int, "errors": int, "policies": [...]}
    """
    repo = repo or DEFAULT_GITHUB_REPO
    branch = branch or DEFAULT_GITHUB_BRANCH
    path = path or DEFAULT_GITHUB_PATH

    result = {"source": "github", "added": 0, "skipped": 0, "errors": 0, "policies": []}

    # Use GitHub API to list directory contents
    api_url = f"https://api.github.com/repos/{repo}/contents/{path}?ref={branch}"
    content = _fetch_url(api_url)
    if not content:
        result["errors"] = 1
        return result

    try:
        files = json.loads(content)
    except json.JSONDecodeError:
        result["errors"] = 1
        return result

    for item in files:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "")
        if not name.endswith(".yaml") and not name.endswith(".yml"):
            continue

        # Fetch raw YAML
        raw_url = item.get("download_url")
        if not raw_url:
            continue

        yaml_content = _fetch_url(raw_url)
        if not yaml_content:
            result["errors"] += 1
            continue

        try:
            if _HAS_YAML:
                policy = yaml.safe_load(yaml_content) or {}
            else:
                continue  # Can't parse without YAML

            if not policy.get("id"):
                continue

            if _policy_exists(policy["id"]):
                result["skipped"] += 1
                continue

            policy["feed_source"] = "github"
            policy["synced_at"] = datetime.now(timezone.utc).isoformat()
            saved = _save_policy_yaml(policy)
            if saved:
                result["added"] += 1
                result["policies"].append(policy["id"])
            else:
                result["skipped"] += 1
        except Exception:
            result["errors"] += 1

    return result


# ---------------------------------------------------------------------------
# Source 2: CIS Benchmarks (Bundled)
# ---------------------------------------------------------------------------

def sync_from_cis(baseline_path: str = None) -> dict:
    """Load CIS Benchmark controls from bundled JSON file.

    Returns: {"source": "cis", "added": int, "skipped": int, "errors": int, "policies": [...]}
    """
    result = {"source": "cis", "added": 0, "skipped": 0, "errors": 0, "policies": []}
    path = baseline_path or _CIS_BASELINE

    if not os.path.exists(path):
        result["errors"] = 1
        logger.warning("CIS baseline file not found: %s", path)
        return result

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        result["errors"] = 1
        logger.error("Failed to parse CIS baseline: %s", exc)
        return result

    controls = data.get("controls", [])
    for ctrl in controls:
        policy_id = ctrl.get("id")
        if not policy_id:
            continue

        if _policy_exists(policy_id):
            result["skipped"] += 1
            continue

        # Convert CIS control to CloudSentry YAML format
        policy = {
            "id": policy_id,
            "name": ctrl.get("name", ""),
            "provider": ctrl.get("provider", "aws"),
            "service": ctrl.get("service", ""),
            "severity": ctrl.get("severity", "MEDIUM"),
            "description": ctrl.get("description", ""),
            "enabled": True,
            "check": ctrl.get("check", ""),
            "remediation": ctrl.get("remediation", ""),
            "auto_remediate": ctrl.get("auto_remediate", False),
            "compliance": [
                {
                    "framework": ctrl.get("framework", "CIS"),
                    "control": ctrl.get("control", ""),
                }
            ],
            "feed_source": "cis",
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }

        saved = _save_policy_yaml(policy)
        if saved:
            result["added"] += 1
            result["policies"].append(policy_id)
        else:
            result["skipped"] += 1

    return result


# ---------------------------------------------------------------------------
# Source 3: Prowler Open-Source
# ---------------------------------------------------------------------------

def sync_from_prowler(provider: str = None) -> dict:
    """Fetch Prowler check metadata from GitHub and convert to CloudSentry YAML.

    Returns: {"source": "prowler", "added": int, "skipped": int, "errors": int, "policies": [...]}
    """
    result = {"source": "prowler", "added": 0, "skipped": 0, "errors": 0, "policies": []}

    providers_to_sync = [provider] if provider else list(PROWLER_CHECKS.keys())

    for prov in providers_to_sync:
        checks = PROWLER_CHECKS.get(prov, [])
        for service, check_name, display_name in checks:
            policy_id = f"prowler-{prov}-{check_name}"

            if _policy_exists(policy_id):
                result["skipped"] += 1
                continue

            # Try to fetch Prowler metadata JSON
            metadata_url = (
                f"{PROWLER_RAW_BASE}/prowler/providers/{prov}/services/{service}/"
                f"{check_name}/{check_name}.metadata.json"
            )

            metadata = {}
            raw = _fetch_url(metadata_url, timeout=5)
            if raw:
                try:
                    metadata = json.loads(raw)
                except json.JSONDecodeError:
                    pass

            # Map Prowler severity to CloudSentry format
            prowler_severity = metadata.get("Severity", "medium").upper()
            severity_map = {
                "INFORMATIONAL": "LOW",
                "LOW": "LOW",
                "MEDIUM": "MEDIUM",
                "HIGH": "HIGH",
                "CRITICAL": "CRITICAL",
            }
            severity = severity_map.get(prowler_severity, "MEDIUM")

            # Build compliance list from Prowler metadata
            compliance = []
            prowler_compliance = metadata.get("Compliance", [])
            for comp in prowler_compliance[:3]:  # Limit to 3
                if isinstance(comp, dict):
                    framework = comp.get("Framework", "")
                    version = comp.get("Version", "")
                    control = comp.get("Control", "")
                    compliance.append({
                        "framework": f"{framework} {version}".strip(),
                        "control": control,
                    })

            if not compliance:
                compliance = [{"framework": "Prowler", "control": check_name}]

            # Create CloudSentry policy
            policy = {
                "id": policy_id,
                "name": metadata.get("CheckTitle", display_name),
                "provider": prov,
                "service": service.rstrip("_"),
                "severity": severity,
                "description": metadata.get("Description", f"Prowler: {display_name}"),
                "enabled": True,
                "check": f"prowler_{check_name}",
                "remediation": metadata.get("Remediation", {}).get("Code", {}).get("CLI", "") if isinstance(metadata.get("Remediation"), dict) else "",
                "auto_remediate": False,
                "compliance": compliance,
                "feed_source": "prowler",
                "prowler_check": check_name,
                "synced_at": datetime.now(timezone.utc).isoformat(),
            }

            saved = _save_policy_yaml(policy)
            if saved:
                result["added"] += 1
                result["policies"].append(policy_id)
            else:
                result["skipped"] += 1

    return result


# ---------------------------------------------------------------------------
# Unified Sync
# ---------------------------------------------------------------------------

def sync_all(
    github_repo: str = None,
    github_branch: str = None,
    github_path: str = None,
) -> dict:
    """Run all 3 sync sources and return combined results.

    Returns: {
        "total_added": int,
        "total_skipped": int,
        "total_errors": int,
        "sources": [github_result, cis_result, prowler_result],
        "timestamp": str,
    }
    """
    results = []

    # 1. GitHub Community
    logger.info("Syncing from GitHub...")
    github_result = sync_from_github(repo=github_repo, branch=github_branch, path=github_path)
    results.append(github_result)

    # 2. CIS Benchmarks
    logger.info("Syncing from CIS Benchmarks...")
    cis_result = sync_from_cis()
    results.append(cis_result)

    # 3. Prowler
    logger.info("Syncing from Prowler...")
    prowler_result = sync_from_prowler()
    results.append(prowler_result)

    total_added = sum(r["added"] for r in results)
    total_skipped = sum(r["skipped"] for r in results)
    total_errors = sum(r["errors"] for r in results)

    return {
        "total_added": total_added,
        "total_skipped": total_skipped,
        "total_errors": total_errors,
        "sources": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
