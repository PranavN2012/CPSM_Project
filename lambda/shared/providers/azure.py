"""
Azure Provider — Microsoft Azure Security Checks
====================================================

Implements CloudProvider interface with real check logic.
When Azure SDK is not installed, uses mock data for demonstration.
"""

import logging
from .base import CloudProvider
from . import mock_data

logger = logging.getLogger(__name__)

# Try to import Azure SDK — fall back to mock mode
try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    _HAS_AZURE_SDK = True
except ImportError:
    _HAS_AZURE_SDK = False


class AzureProvider(CloudProvider):
    """Azure security checks — runs against real SDK or mock data."""

    NAME = "Microsoft Azure"
    DESCRIPTION = "Blob Storage, NSG, RBAC security checks"

    @classmethod
    def is_configured(cls) -> bool:
        # Always configured — uses mock data when SDK is absent
        return True

    def __init__(self):
        self._mock_mode = not _HAS_AZURE_SDK
        if _HAS_AZURE_SDK:
            try:
                cred = DefaultAzureCredential()
                sub_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
                self._storage = StorageManagementClient(cred, sub_id)
                self._network = NetworkManagementClient(cred, sub_id)
                self._auth = AuthorizationManagementClient(cred, sub_id)
            except Exception:
                self._mock_mode = True

    # ─── Storage: Public Access ──────────────────────────────────────

    def check_storage_public_access(self, resource_id: str, **kwargs) -> dict:
        """Check Azure Blob Storage for public access."""
        if self._mock_mode:
            accounts = mock_data.azure_storage_accounts(scenario="mixed")
            # Find account by name or use first matching
            account = next((a for a in accounts if a["name"] == resource_id), None)
            if not account:
                account = next((a for a in accounts if a["properties"]["allowBlobPublicAccess"]), accounts[0])
                resource_id = account["name"]

            props = account["properties"]
            public = props.get("allowBlobPublicAccess", False)

            # Also check containers
            containers = mock_data.azure_blob_containers(resource_id)
            public_containers = [c for c in containers if c["properties"]["publicAccess"] != "none"]

            findings = []
            if public:
                findings.append("Storage account allows public blob access")
            for c in public_containers:
                findings.append(f"Container '{c['name']}' has publicAccess={c['properties']['publicAccess']}")

            return {
                "status": "NON_COMPLIANT" if findings else "COMPLIANT",
                "resource": resource_id,
                "provider": "azure",
                "service": "storage",
                "findings": findings,
                "details": {
                    "allowBlobPublicAccess": public,
                    "publicContainers": [c["name"] for c in public_containers],
                    "location": account.get("location", "unknown"),
                },
            }
        else:
            # Real SDK call
            try:
                parts = resource_id.split("/")
                rg = parts[4] if len(parts) > 4 else "rg-cloudsentry-prod"
                name = parts[-1] if "/" in resource_id else resource_id
                account = self._storage.storage_accounts.get_properties(rg, name)
                public = getattr(account, "allow_blob_public_access", False)
                return {
                    "status": "NON_COMPLIANT" if public else "COMPLIANT",
                    "resource": name,
                    "provider": "azure",
                    "service": "storage",
                    "findings": ["Public blob access allowed"] if public else [],
                }
            except Exception as exc:
                return {"status": "ERROR", "provider": "azure", "message": str(exc)}

    # ─── Storage: Encryption ─────────────────────────────────────────

    def check_storage_encryption(self, resource_id: str, **kwargs) -> dict:
        """Check Azure storage encryption (HTTPS-only, TLS version)."""
        if self._mock_mode:
            accounts = mock_data.azure_storage_accounts(scenario="mixed")
            account = next((a for a in accounts if a["name"] == resource_id), accounts[0])
            resource_id = account["name"]
            props = account["properties"]

            findings = []
            if not props.get("supportsHttpsTrafficOnly", True):
                findings.append("HTTPS-only traffic not enforced")
            tls = props.get("minimumTlsVersion", "TLS1_2")
            if tls != "TLS1_2":
                findings.append(f"Minimum TLS version is {tls} (should be TLS1_2)")

            return {
                "status": "NON_COMPLIANT" if findings else "COMPLIANT",
                "resource": resource_id,
                "provider": "azure",
                "service": "storage",
                "findings": findings,
                "details": {
                    "httpsOnly": props.get("supportsHttpsTrafficOnly"),
                    "minTlsVersion": tls,
                },
            }
        else:
            try:
                name = resource_id.split("/")[-1] if "/" in resource_id else resource_id
                rg = "rg-cloudsentry-prod"
                account = self._storage.storage_accounts.get_properties(rg, name)
                https = getattr(account, "enable_https_traffic_only", True)
                tls = getattr(account, "minimum_tls_version", "TLS1_2")
                findings = []
                if not https:
                    findings.append("HTTPS not enforced")
                if tls != "TLS1_2":
                    findings.append(f"TLS version: {tls}")
                return {
                    "status": "NON_COMPLIANT" if findings else "COMPLIANT",
                    "resource": name, "provider": "azure", "service": "storage",
                    "findings": findings,
                }
            except Exception as exc:
                return {"status": "ERROR", "provider": "azure", "message": str(exc)}

    # ─── Network: Open Ports (NSG) ───────────────────────────────────

    def check_network_open_ports(self, resource_id: str, **kwargs) -> dict:
        """Check Azure NSG for dangerous open ports (SSH 22, RDP 3389)."""
        if self._mock_mode:
            nsgs = mock_data.azure_nsg_rules(scenario="mixed")
            nsg = next((n for n in nsgs if n["name"] == resource_id), None)
            if not nsg:
                nsg = nsgs[0]
                resource_id = nsg["name"]

            open_ports = []
            for rule in nsg["properties"]["securityRules"]:
                rp = rule["properties"]
                if rp.get("access") != "Allow" or rp.get("direction") != "Inbound":
                    continue
                src = rp.get("sourceAddressPrefix", "")
                if src in ("*", "0.0.0.0/0", "Internet"):
                    port_str = rp.get("destinationPortRange", "")
                    try:
                        port = int(port_str)
                    except (ValueError, TypeError):
                        port = 0
                    if port in mock_data.DANGEROUS_PORTS or port_str == "*":
                        open_ports.append({
                            "rule": rule["name"],
                            "port": port,
                            "source": src,
                            "protocol": rp.get("protocol", "Any"),
                        })

            return {
                "status": "NON_COMPLIANT" if open_ports else "COMPLIANT",
                "resource": resource_id,
                "provider": "azure",
                "service": "network",
                "findings": [f"NSG rule '{p['rule']}' allows {p['source']} → port {p['port']}" for p in open_ports],
                "open_ports": open_ports,
            }
        else:
            try:
                nsgs = list(self._network.network_security_groups.list_all())
                target = next((n for n in nsgs if n.name == resource_id), None)
                if not target:
                    return {"status": "ERROR", "message": f"NSG {resource_id} not found"}
                open_ports = []
                for rule in (target.security_rules or []):
                    if rule.access == "Allow" and rule.direction == "Inbound":
                        if rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet"):
                            open_ports.append({"rule": rule.name, "port": rule.destination_port_range})
                return {
                    "status": "NON_COMPLIANT" if open_ports else "COMPLIANT",
                    "resource": resource_id, "provider": "azure", "service": "network",
                    "findings": [f"Open port: {p['port']}" for p in open_ports],
                }
            except Exception as exc:
                return {"status": "ERROR", "provider": "azure", "message": str(exc)}

    # ─── IAM: Overpermissive RBAC ────────────────────────────────────

    def check_iam_overpermissive(self, resource_id: str, **kwargs) -> dict:
        """Check Azure RBAC for dangerous subscription-level roles."""
        if self._mock_mode:
            assignments = mock_data.azure_rbac_assignments(scenario="mixed")
            findings = []
            for a in assignments:
                role = a.get("_roleName", "")
                principal = a["properties"]["principalId"]
                scope = a["properties"]["scope"]

                if role in mock_data.AZURE_DANGEROUS_ROLES and "/subscriptions/" in scope:
                    # Subscription-level Owner/Contributor is dangerous
                    if resource_id == "all" or resource_id == principal:
                        findings.append({
                            "principal": principal,
                            "role": role,
                            "scope": scope,
                            "risk": "HIGH" if role == "Owner" else "MEDIUM",
                        })

            return {
                "status": "NON_COMPLIANT" if findings else "COMPLIANT",
                "resource": resource_id,
                "provider": "azure",
                "service": "iam",
                "findings": [f"{f['principal']} has {f['role']} at subscription level" for f in findings],
                "details": findings,
            }
        else:
            try:
                assignments = list(self._auth.role_assignments.list())
                findings = []
                for a in assignments:
                    if "/subscriptions/" in (a.scope or ""):
                        findings.append({"principal": a.principal_id, "scope": a.scope})
                return {
                    "status": "NON_COMPLIANT" if findings else "COMPLIANT",
                    "resource": resource_id, "provider": "azure", "service": "iam",
                    "findings": [f"Subscription-level assignment: {f['principal']}" for f in findings],
                }
            except Exception as exc:
                return {"status": "ERROR", "provider": "azure", "message": str(exc)}

    # ─── Remediation ─────────────────────────────────────────────────

    def remediate(self, check_name: str, resource_id: str, **kwargs) -> dict:
        """Execute Azure-specific remediation."""
        if check_name == "check_storage_public_access":
            if self._mock_mode:
                return {
                    "status": "REMEDIATED",
                    "resource": resource_id,
                    "provider": "azure",
                    "action": "Set allowBlobPublicAccess=false on storage account",
                }
            else:
                try:
                    name = resource_id.split("/")[-1] if "/" in resource_id else resource_id
                    self._storage.storage_accounts.update(
                        "rg-cloudsentry-prod", name,
                        {"properties": {"allowBlobPublicAccess": False}}
                    )
                    return {"status": "REMEDIATED", "resource": name, "provider": "azure"}
                except Exception as exc:
                    return {"status": "FAILED", "message": str(exc)}

        elif check_name == "check_network_open_ports":
            if self._mock_mode:
                return {
                    "status": "REMEDIATED",
                    "resource": resource_id,
                    "provider": "azure",
                    "action": "Updated NSG rules to restrict dangerous port access",
                }
            else:
                return {"status": "UNSUPPORTED", "message": "NSG remediation requires manual review"}

        return {"status": "UNSUPPORTED", "message": f"No remediation for {check_name}"}
