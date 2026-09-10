"""
Mock Data Layer — Realistic Azure & GCP API Responses
=======================================================

Provides configurable mock data so the Azure and GCP providers can
execute real check logic without requiring cloud SDK installations.

Each function returns data structures that mirror the actual cloud
API responses (Azure REST API and GCP JSON API formats).
"""

import random
import uuid
from datetime import datetime, timezone

# ═══════════════════════════════════════════════════════════════════
# AZURE MOCK DATA
# ═══════════════════════════════════════════════════════════════════

AZURE_SUBSCRIPTIONS = [
    {"id": "/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
     "display_name": "CloudSentry-Production", "state": "Enabled"},
]

AZURE_RESOURCE_GROUPS = ["rg-cloudsentry-prod", "rg-data-platform", "rg-web-frontend"]


def azure_storage_accounts(scenario="mixed"):
    """Return mock Azure storage accounts with varying security postures.

    Scenarios: 'compliant', 'non_compliant', 'mixed'
    """
    accounts = [
        {
            "id": "/subscriptions/a1b2c3d4/resourceGroups/rg-cloudsentry-prod/providers/Microsoft.Storage/storageAccounts/csproddata01",
            "name": "csproddata01",
            "type": "Microsoft.Storage/storageAccounts",
            "location": "eastus",
            "properties": {
                "supportsHttpsTrafficOnly": True,
                "minimumTlsVersion": "TLS1_2",
                "allowBlobPublicAccess": False,
                "encryption": {
                    "services": {
                        "blob": {"enabled": True, "keyType": "Account"},
                        "file": {"enabled": True, "keyType": "Account"},
                    },
                    "keySource": "Microsoft.Storage",
                },
            },
        },
        {
            "id": "/subscriptions/a1b2c3d4/resourceGroups/rg-data-platform/providers/Microsoft.Storage/storageAccounts/devuploadstemp",
            "name": "devuploadstemp",
            "type": "Microsoft.Storage/storageAccounts",
            "location": "westus2",
            "properties": {
                "supportsHttpsTrafficOnly": False,
                "minimumTlsVersion": "TLS1_0",
                "allowBlobPublicAccess": True,
                "encryption": {
                    "services": {
                        "blob": {"enabled": True, "keyType": "Account"},
                    },
                    "keySource": "Microsoft.Storage",
                },
            },
        },
        {
            "id": "/subscriptions/a1b2c3d4/resourceGroups/rg-web-frontend/providers/Microsoft.Storage/storageAccounts/staticwebcontent",
            "name": "staticwebcontent",
            "type": "Microsoft.Storage/storageAccounts",
            "location": "eastus",
            "properties": {
                "supportsHttpsTrafficOnly": True,
                "minimumTlsVersion": "TLS1_2",
                "allowBlobPublicAccess": True,
                "encryption": {
                    "services": {
                        "blob": {"enabled": True, "keyType": "Account"},
                    },
                    "keySource": "Microsoft.Storage",
                },
            },
        },
    ]

    if scenario == "compliant":
        for a in accounts:
            a["properties"]["allowBlobPublicAccess"] = False
            a["properties"]["supportsHttpsTrafficOnly"] = True
            a["properties"]["minimumTlsVersion"] = "TLS1_2"
    elif scenario == "non_compliant":
        for a in accounts:
            a["properties"]["allowBlobPublicAccess"] = True
            a["properties"]["supportsHttpsTrafficOnly"] = False

    return accounts


def azure_blob_containers(storage_account, scenario="mixed"):
    """Return mock blob containers for a storage account."""
    containers = [
        {"name": "uploads", "properties": {"publicAccess": "blob"}},
        {"name": "backups", "properties": {"publicAccess": "none"}},
        {"name": "logs", "properties": {"publicAccess": "container"}},
    ]
    if scenario == "compliant":
        for c in containers:
            c["properties"]["publicAccess"] = "none"
    return containers


def azure_nsg_rules(scenario="mixed"):
    """Return mock NSG rules — some allowing 0.0.0.0/0 on dangerous ports."""
    return [
        {
            "id": "/subscriptions/a1b2c3d4/resourceGroups/rg-cloudsentry-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web-tier",
            "name": "nsg-web-tier",
            "location": "eastus",
            "properties": {
                "securityRules": [
                    {
                        "name": "AllowHTTPS",
                        "properties": {
                            "protocol": "TCP", "sourceAddressPrefix": "*",
                            "destinationPortRange": "443",
                            "access": "Allow", "direction": "Inbound", "priority": 100,
                        },
                    },
                    {
                        "name": "AllowSSH_UNSAFE" if scenario != "compliant" else "DenySSH",
                        "properties": {
                            "protocol": "TCP",
                            "sourceAddressPrefix": "0.0.0.0/0" if scenario != "compliant" else "10.0.0.0/8",
                            "destinationPortRange": "22",
                            "access": "Allow" if scenario != "compliant" else "Deny",
                            "direction": "Inbound", "priority": 200,
                        },
                    },
                ],
            },
        },
        {
            "id": "/subscriptions/a1b2c3d4/resourceGroups/rg-data-platform/providers/Microsoft.Network/networkSecurityGroups/nsg-db-tier",
            "name": "nsg-db-tier",
            "location": "eastus",
            "properties": {
                "securityRules": [
                    {
                        "name": "AllowRDP_UNSAFE",
                        "properties": {
                            "protocol": "TCP",
                            "sourceAddressPrefix": "0.0.0.0/0" if scenario != "compliant" else "10.0.0.0/8",
                            "destinationPortRange": "3389",
                            "access": "Allow", "direction": "Inbound", "priority": 100,
                        },
                    },
                    {
                        "name": "AllowSQL",
                        "properties": {
                            "protocol": "TCP", "sourceAddressPrefix": "10.0.0.0/8",
                            "destinationPortRange": "1433",
                            "access": "Allow", "direction": "Inbound", "priority": 200,
                        },
                    },
                ],
            },
        },
    ]


def azure_rbac_assignments(scenario="mixed"):
    """Return mock RBAC role assignments."""
    return [
        {
            "id": "/subscriptions/a1b2c3d4/providers/Microsoft.Authorization/roleAssignments/ra-001",
            "properties": {
                "roleDefinitionId": "/subscriptions/a1b2c3d4/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                "principalId": "user-admin-001",
                "principalType": "User",
                "scope": "/subscriptions/a1b2c3d4",
            },
            "_roleName": "Owner",
        },
        {
            "id": "/subscriptions/a1b2c3d4/providers/Microsoft.Authorization/roleAssignments/ra-002",
            "properties": {
                "roleDefinitionId": "/subscriptions/a1b2c3d4/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
                "principalId": "user-dev-intern-001",
                "principalType": "User",
                "scope": "/subscriptions/a1b2c3d4",
            },
            "_roleName": "Contributor",
        },
        {
            "id": "/subscriptions/a1b2c3d4/providers/Microsoft.Authorization/roleAssignments/ra-003",
            "properties": {
                "roleDefinitionId": "/subscriptions/a1b2c3d4/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
                "principalId": "user-reader-001",
                "principalType": "User",
                "scope": "/subscriptions/a1b2c3d4",
            },
            "_roleName": "Reader",
        },
    ]


# ═══════════════════════════════════════════════════════════════════
# GCP MOCK DATA
# ═══════════════════════════════════════════════════════════════════

GCP_PROJECTS = [
    {"projectId": "cloudsentry-prod-2026", "name": "CloudSentry Production", "lifecycleState": "ACTIVE"},
]


def gcp_storage_buckets(scenario="mixed"):
    """Return mock GCS buckets with varying IAM and encryption settings."""
    buckets = [
        {
            "name": "cs-prod-data-lake",
            "location": "US",
            "storageClass": "STANDARD",
            "iamConfiguration": {
                "uniformBucketLevelAccess": {"enabled": True},
                "publicAccessPrevention": "enforced",
            },
            "encryption": {"defaultKmsKeyName": "projects/cloudsentry-prod/locations/us/keyRings/cspm-ring/cryptoKeys/bucket-key"},
            "_iam_bindings": [
                {"role": "roles/storage.objectViewer", "members": ["serviceAccount:data-pipeline@cloudsentry-prod.iam.gserviceaccount.com"]},
            ],
        },
        {
            "name": "dev-uploads-temp",
            "location": "US-CENTRAL1",
            "storageClass": "STANDARD",
            "iamConfiguration": {
                "uniformBucketLevelAccess": {"enabled": False},
                "publicAccessPrevention": "inherited",
            },
            "encryption": {},
            "_iam_bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                {"role": "roles/storage.objectCreator", "members": ["allAuthenticatedUsers"]},
            ],
        },
        {
            "name": "static-web-assets",
            "location": "US",
            "storageClass": "STANDARD",
            "iamConfiguration": {
                "uniformBucketLevelAccess": {"enabled": True},
                "publicAccessPrevention": "inherited",
            },
            "encryption": {},
            "_iam_bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
            ],
        },
    ]

    if scenario == "compliant":
        for b in buckets:
            b["iamConfiguration"]["publicAccessPrevention"] = "enforced"
            b["_iam_bindings"] = [ib for ib in b["_iam_bindings"] if "allUsers" not in str(ib["members"]) and "allAuthenticatedUsers" not in str(ib["members"])]
    return buckets


def gcp_firewall_rules(scenario="mixed"):
    """Return mock GCP VPC firewall rules."""
    return [
        {
            "name": "allow-https",
            "network": "projects/cloudsentry-prod/global/networks/default",
            "direction": "INGRESS",
            "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
            "sourceRanges": ["0.0.0.0/0"],
            "priority": 1000,
            "disabled": False,
        },
        {
            "name": "allow-ssh-all" if scenario != "compliant" else "allow-ssh-internal",
            "network": "projects/cloudsentry-prod/global/networks/default",
            "direction": "INGRESS",
            "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            "sourceRanges": ["0.0.0.0/0"] if scenario != "compliant" else ["10.0.0.0/8"],
            "priority": 1000,
            "disabled": False,
        },
        {
            "name": "allow-rdp-all",
            "network": "projects/cloudsentry-prod/global/networks/default",
            "direction": "INGRESS",
            "allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}],
            "sourceRanges": ["0.0.0.0/0"] if scenario != "compliant" else ["10.0.0.0/8"],
            "priority": 1000,
            "disabled": False,
        },
    ]


def gcp_iam_bindings(scenario="mixed"):
    """Return mock GCP IAM bindings at project level."""
    bindings = [
        {"role": "roles/owner", "members": ["user:admin@cloudsentry.io"]},
        {"role": "roles/editor", "members": ["user:dev-intern@cloudsentry.io", "serviceAccount:ci-cd@cloudsentry-prod.iam.gserviceaccount.com"]},
        {"role": "roles/viewer", "members": ["user:analyst@cloudsentry.io"]},
    ]
    if scenario == "compliant":
        bindings = [b for b in bindings if b["role"] not in ("roles/owner", "roles/editor")]
    return bindings


# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

DANGEROUS_PORTS = {22, 3389, 1433, 3306, 5432, 27017}

AZURE_DANGEROUS_ROLES = {"Owner", "Contributor", "User Access Administrator"}
GCP_DANGEROUS_ROLES = {"roles/owner", "roles/editor"}


def make_event_id():
    return str(uuid.uuid4())


def now_iso():
    return datetime.now(timezone.utc).isoformat()
