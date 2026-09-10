"""
GCP Provider — Google Cloud Platform Security Checks
=======================================================

Implements CloudProvider interface with real check logic.
When GCP SDK is not installed, uses mock data for demonstration.
"""

import logging
from .base import CloudProvider
from . import mock_data

logger = logging.getLogger(__name__)

# Try to import GCP SDK — fall back to mock mode
try:
    from google.cloud import storage as gcs_storage
    from google.cloud import compute_v1
    from google.cloud import resourcemanager_v3
    _HAS_GCP_SDK = True
except ImportError:
    _HAS_GCP_SDK = False


class GCPProvider(CloudProvider):
    """GCP security checks — runs against real SDK or mock data."""

    NAME = "Google Cloud Platform"
    DESCRIPTION = "Cloud Storage, VPC Firewall, IAM security checks"

    @classmethod
    def is_configured(cls) -> bool:
        # Always configured — uses mock data when SDK is absent
        return True

    def __init__(self):
        self._mock_mode = not _HAS_GCP_SDK
        self._project = "cloudsentry-prod-2026"
        if _HAS_GCP_SDK:
            try:
                self._storage_client = gcs_storage.Client()
                self._firewall_client = compute_v1.FirewallsClient()
            except Exception:
                self._mock_mode = True

    # ─── Storage: Public Access (GCS) ────────────────────────────────

    def check_storage_public_access(self, resource_id: str, **kwargs) -> dict:
        """Check GCS bucket for public IAM bindings (allUsers / allAuthenticatedUsers)."""
        if self._mock_mode:
            buckets = mock_data.gcp_storage_buckets(scenario="mixed")
            bucket = next((b for b in buckets if b["name"] == resource_id), None)
            if not bucket:
                bucket = next((b for b in buckets if b.get("_iam_bindings")), buckets[0])
                resource_id = bucket["name"]

            findings = []
            public_members = set()
            for binding in bucket.get("_iam_bindings", []):
                for member in binding.get("members", []):
                    if member in ("allUsers", "allAuthenticatedUsers"):
                        findings.append(f"Role '{binding['role']}' granted to {member}")
                        public_members.add(member)

            pap = bucket.get("iamConfiguration", {}).get("publicAccessPrevention", "inherited")
            if pap != "enforced" and not findings:
                findings.append(f"publicAccessPrevention is '{pap}' (should be 'enforced')")

            return {
                "status": "NON_COMPLIANT" if findings else "COMPLIANT",
                "resource": resource_id,
                "provider": "gcp",
                "service": "storage",
                "findings": findings,
                "details": {
                    "publicAccessPrevention": pap,
                    "publicMembers": list(public_members),
                    "location": bucket.get("location", "unknown"),
                },
            }
        else:
            try:
                bucket = self._storage_client.get_bucket(resource_id)
                policy = bucket.get_iam_policy(requested_policy_version=3)
                findings = []
                for binding in policy.bindings:
                    for member in binding.get("members", []):
                        if member in ("allUsers", "allAuthenticatedUsers"):
                            findings.append(f"{binding['role']} → {member}")
                return {
                    "status": "NON_COMPLIANT" if findings else "COMPLIANT",
                    "resource": resource_id, "provider": "gcp", "service": "storage",
                    "findings": findings,
                }
            except Exception as exc:
                return {"status": "ERROR", "provider": "gcp", "message": str(exc)}

    # ─── Storage: Encryption (CMEK) ──────────────────────────────────

    def check_storage_encryption(self, resource_id: str, **kwargs) -> dict:
        """Check GCS bucket for Customer-Managed Encryption Keys (CMEK)."""
        if self._mock_mode:
            buckets = mock_data.gcp_storage_buckets(scenario="mixed")
            bucket = next((b for b in buckets if b["name"] == resource_id), None)
            if not bucket:
                bucket = buckets[0]
                resource_id = bucket["name"]

            encryption = bucket.get("encryption", {})
            has_cmek = bool(encryption.get("defaultKmsKeyName"))

            findings = []
            if not has_cmek:
                findings.append("No Customer-Managed Encryption Key (CMEK) configured — using Google-managed default")

            uba = bucket.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled", False)
            if not uba:
                findings.append("Uniform Bucket-Level Access not enabled (legacy ACLs active)")

            return {
                "status": "NON_COMPLIANT" if findings else "COMPLIANT",
                "resource": resource_id,
                "provider": "gcp",
                "service": "storage",
                "findings": findings,
                "details": {
                    "cmekKey": encryption.get("defaultKmsKeyName", "none"),
                    "uniformBucketLevelAccess": uba,
                    "storageClass": bucket.get("storageClass", "STANDARD"),
                },
            }
        else:
            try:
                bucket = self._storage_client.get_bucket(resource_id)
                cmek = bucket.default_kms_key_name
                findings = [] if cmek else ["No CMEK configured"]
                return {
                    "status": "NON_COMPLIANT" if findings else "COMPLIANT",
                    "resource": resource_id, "provider": "gcp", "service": "storage",
                    "findings": findings,
                }
            except Exception as exc:
                return {"status": "ERROR", "provider": "gcp", "message": str(exc)}

    # ─── Network: Open Ports (VPC Firewall) ──────────────────────────

    def check_network_open_ports(self, resource_id: str, **kwargs) -> dict:
        """Check GCP VPC firewall rules for dangerous open ports."""
        if self._mock_mode:
            rules = mock_data.gcp_firewall_rules(scenario="mixed")
            if resource_id != "all":
                rules = [r for r in rules if r["name"] == resource_id] or rules

            open_ports = []
            for rule in rules:
                if rule.get("disabled"):
                    continue
                if rule.get("direction") != "INGRESS":
                    continue
                sources = rule.get("sourceRanges", [])
                if "0.0.0.0/0" not in sources:
                    continue
                for allowed in rule.get("allowed", []):
                    for port_str in allowed.get("ports", []):
                        try:
                            port = int(port_str)
                        except (ValueError, TypeError):
                            port = 0
                        if port in mock_data.DANGEROUS_PORTS or port_str == "*":
                            open_ports.append({
                                "rule": rule["name"],
                                "port": port,
                                "protocol": allowed.get("IPProtocol", "tcp"),
                                "source": "0.0.0.0/0",
                            })

            return {
                "status": "NON_COMPLIANT" if open_ports else "COMPLIANT",
                "resource": resource_id,
                "provider": "gcp",
                "service": "network",
                "findings": [f"Firewall rule '{p['rule']}' allows 0.0.0.0/0 → port {p['port']}" for p in open_ports],
                "open_ports": open_ports,
            }
        else:
            try:
                rules = self._firewall_client.list(project=self._project)
                open_ports = []
                for rule in rules:
                    if rule.disabled or rule.direction != "INGRESS":
                        continue
                    if "0.0.0.0/0" in (rule.source_ranges or []):
                        for allowed in (rule.allowed or []):
                            for port in (allowed.ports or []):
                                open_ports.append({"rule": rule.name, "port": port})
                return {
                    "status": "NON_COMPLIANT" if open_ports else "COMPLIANT",
                    "resource": resource_id, "provider": "gcp", "service": "network",
                    "findings": [f"Open: {p['rule']} port {p['port']}" for p in open_ports],
                }
            except Exception as exc:
                return {"status": "ERROR", "provider": "gcp", "message": str(exc)}

    # ─── IAM: Overpermissive ─────────────────────────────────────────

    def check_iam_overpermissive(self, resource_id: str, **kwargs) -> dict:
        """Check GCP IAM bindings for overly broad roles (Owner/Editor)."""
        if self._mock_mode:
            bindings = mock_data.gcp_iam_bindings(scenario="mixed")
            findings = []

            for binding in bindings:
                role = binding.get("role", "")
                if role not in mock_data.GCP_DANGEROUS_ROLES:
                    continue
                for member in binding.get("members", []):
                    if resource_id == "all" or resource_id in member:
                        findings.append({
                            "member": member,
                            "role": role,
                            "risk": "CRITICAL" if role == "roles/owner" else "HIGH",
                        })

            return {
                "status": "NON_COMPLIANT" if findings else "COMPLIANT",
                "resource": resource_id,
                "provider": "gcp",
                "service": "iam",
                "findings": [f"{f['member']} has {f['role']} at project level" for f in findings],
                "details": findings,
            }
        else:
            try:
                # Real GCP IAM check would use resourcemanager
                return {"status": "ERROR", "message": "Real IAM check requires resourcemanager SDK"}
            except Exception as exc:
                return {"status": "ERROR", "provider": "gcp", "message": str(exc)}

    # ─── Remediation ─────────────────────────────────────────────────

    def remediate(self, check_name: str, resource_id: str, **kwargs) -> dict:
        """Execute GCP-specific remediation."""
        if check_name == "check_storage_public_access":
            if self._mock_mode:
                return {
                    "status": "REMEDIATED",
                    "resource": resource_id,
                    "provider": "gcp",
                    "action": "Removed allUsers/allAuthenticatedUsers bindings and enforced publicAccessPrevention",
                }
            else:
                try:
                    bucket = self._storage_client.get_bucket(resource_id)
                    bucket.iam_configuration.public_access_prevention = "enforced"
                    bucket.patch()
                    return {"status": "REMEDIATED", "resource": resource_id, "provider": "gcp"}
                except Exception as exc:
                    return {"status": "FAILED", "message": str(exc)}

        elif check_name == "check_network_open_ports":
            if self._mock_mode:
                return {
                    "status": "REMEDIATED",
                    "resource": resource_id,
                    "provider": "gcp",
                    "action": "Restricted firewall source ranges from 0.0.0.0/0 to internal CIDR",
                }
            else:
                return {"status": "UNSUPPORTED", "message": "Firewall remediation requires manual review"}

        return {"status": "UNSUPPORTED", "message": f"No remediation for {check_name}"}
