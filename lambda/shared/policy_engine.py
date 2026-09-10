"""
Policy Engine — YAML-Based Cloud-Agnostic Policy Management
=============================================================

Loads security policies from YAML files, filters by provider/status,
and provides CRUD operations for toggling and editing policies.

This is the same Policy-as-Code approach used by Cloud Custodian,
Prisma Cloud, and OPA — but using YAML instead of Rego for simplicity.
"""

import os
import glob
import logging

# PyYAML is available in Lambda runtimes and pip
try:
    import yaml
except ImportError:
    # Fallback: minimal YAML parser for environments without PyYAML
    yaml = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Policy Directory
# ---------------------------------------------------------------------------

_POLICIES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "policies"
)

# In-memory policy cache
_policy_cache: dict = {}


# ---------------------------------------------------------------------------
# YAML Parsing (with fallback)
# ---------------------------------------------------------------------------

def _parse_yaml(filepath: str) -> dict:
    """Parse a YAML file into a dict."""
    if yaml:
        with open(filepath, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    # Minimal fallback parser for simple flat YAML
    result = {}
    current_list_key = None
    current_list = []
    current_item = {}

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.rstrip()
            if not stripped or stripped.startswith("#"):
                continue

            # List item
            if stripped.startswith("  - ") and current_list_key:
                if current_item:
                    current_list.append(current_item)
                current_item = {}
                kv = stripped[4:].split(":", 1)
                if len(kv) == 2:
                    current_item[kv[0].strip()] = kv[1].strip().strip('"').strip("'")
                continue

            if stripped.startswith("    ") and current_list_key:
                kv = stripped.strip().split(":", 1)
                if len(kv) == 2:
                    current_item[kv[0].strip()] = kv[1].strip().strip('"').strip("'")
                continue

            # New top-level key
            if current_list_key and current_item:
                current_list.append(current_item)
                current_item = {}
            if current_list_key and current_list:
                result[current_list_key] = current_list
                current_list = []
                current_list_key = None

            kv = stripped.split(":", 1)
            if len(kv) == 2:
                key = kv[0].strip()
                val = kv[1].strip().strip('"').strip("'")
                if val == "":
                    current_list_key = key
                    current_list = []
                elif val.lower() == "true":
                    result[key] = True
                elif val.lower() == "false":
                    result[key] = False
                else:
                    result[key] = val

    if current_list_key and current_item:
        current_list.append(current_item)
    if current_list_key and current_list:
        result[current_list_key] = current_list

    return result


def _write_yaml(filepath: str, data: dict):
    """Write a dict back to YAML."""
    if yaml:
        with open(filepath, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        return

    # Minimal fallback writer
    with open(filepath, "w", encoding="utf-8") as f:
        for key, val in data.items():
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


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------

def load_policies(policies_dir: str = None, force_reload: bool = False) -> list[dict]:
    """Load all YAML policies from the policies directory."""
    global _policy_cache
    if _policy_cache and not force_reload:
        return list(_policy_cache.values())

    pdir = policies_dir or _POLICIES_DIR
    _policy_cache = {}

    if not os.path.isdir(pdir):
        logger.warning("Policies directory not found: %s", pdir)
        return []

    for filepath in sorted(glob.glob(os.path.join(pdir, "*.yaml"))):
        try:
            policy = _parse_yaml(filepath)
            if "id" in policy:
                policy["_filepath"] = filepath
                _policy_cache[policy["id"]] = policy
        except Exception as exc:
            logger.error("Failed to parse policy %s: %s", filepath, exc)

    logger.info("Loaded %d policies from %s", len(_policy_cache), pdir)
    return list(_policy_cache.values())


def get_policy(policy_id: str) -> dict | None:
    """Get a single policy by ID."""
    if not _policy_cache:
        load_policies()
    return _policy_cache.get(policy_id)


def get_enabled_policies(provider: str = None) -> list[dict]:
    """Get all enabled policies, optionally filtered by provider."""
    policies = load_policies()
    enabled = [p for p in policies if p.get("enabled", True)]
    if provider:
        enabled = [p for p in enabled if p.get("provider") == provider]
    return enabled


def get_providers() -> list[dict]:
    """Get a list of unique providers from loaded policies."""
    policies = load_policies()
    providers = {}
    for p in policies:
        prov = p.get("provider", "unknown")
        if prov not in providers:
            providers[prov] = {
                "name": prov.upper(),
                "slug": prov,
                "policy_count": 0,
                "active_count": 0,
            }
        providers[prov]["policy_count"] += 1
        if p.get("enabled", True):
            providers[prov]["active_count"] += 1

    return list(providers.values())


def update_policy(policy_id: str, updates: dict) -> dict | None:
    """Update a policy's fields and persist to YAML file.

    Supported fields: enabled, severity, description, auto_remediate
    """
    if not _policy_cache:
        load_policies()

    policy = _policy_cache.get(policy_id)
    if not policy:
        return None

    allowed_fields = {"enabled", "severity", "description", "auto_remediate"}
    filepath = policy.get("_filepath")

    for key, val in updates.items():
        if key in allowed_fields:
            policy[key] = val

    _policy_cache[policy_id] = policy

    # Persist to disk
    if filepath:
        try:
            write_data = {k: v for k, v in policy.items() if not k.startswith("_")}
            _write_yaml(filepath, write_data)
        except Exception as exc:
            logger.error("Failed to persist policy %s: %s", policy_id, exc)

    return policy


def is_check_enabled(check_name: str) -> bool:
    """Quick check if a specific check function is enabled in any policy."""
    if not _policy_cache:
        load_policies()
    for p in _policy_cache.values():
        if p.get("check") == check_name:
            return p.get("enabled", True)
    return True  # Default to enabled if policy not found


def policies_to_json() -> list[dict]:
    """Return all policies as JSON-serializable list (without file paths)."""
    policies = load_policies()
    return [
        {k: v for k, v in p.items() if not k.startswith("_")}
        for p in policies
    ]
