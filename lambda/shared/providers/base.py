"""
CloudProvider — Abstract Base Class
=====================================

Defines the common interface that all cloud providers must implement.
Follows the Strategy Pattern (same architecture as Terraform providers).
"""

from abc import ABC, abstractmethod


class CloudProvider(ABC):
    """Abstract base class for cloud provider security checks."""

    NAME: str = "Unknown"
    DESCRIPTION: str = "Abstract cloud provider"

    @classmethod
    def is_configured(cls) -> bool:
        """Check if this provider's credentials/SDK are available."""
        return False

    @abstractmethod
    def check_storage_public_access(self, resource_id: str, **kwargs) -> dict:
        """Check if a storage resource has public access enabled."""
        ...

    @abstractmethod
    def check_storage_encryption(self, resource_id: str, **kwargs) -> dict:
        """Check if a storage resource has encryption enabled."""
        ...

    @abstractmethod
    def check_network_open_ports(self, resource_id: str, **kwargs) -> dict:
        """Check if a network resource has unsafe open ports."""
        ...

    @abstractmethod
    def check_iam_overpermissive(self, resource_id: str, **kwargs) -> dict:
        """Check if IAM policies are overly permissive."""
        ...

    @abstractmethod
    def remediate(self, check_name: str, resource_id: str, **kwargs) -> dict:
        """Execute remediation for a specific check."""
        ...

    def get_capabilities(self) -> list[str]:
        """Return list of supported check names."""
        return [
            "check_storage_public_access",
            "check_storage_encryption",
            "check_network_open_ports",
            "check_iam_overpermissive",
        ]
