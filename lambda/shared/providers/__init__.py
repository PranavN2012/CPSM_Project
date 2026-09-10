"""
Cloud Provider Abstraction Layer — Provider Registry
=====================================================

Maps provider slugs (aws, azure, gcp) to their implementing classes.
"""

from .base import CloudProvider
from .aws import AWSProvider
from .azure import AzureProvider
from .gcp import GCPProvider

# Provider Registry
PROVIDERS = {
    "aws": AWSProvider,
    "azure": AzureProvider,
    "gcp": GCPProvider,
}


def get_provider(name: str) -> CloudProvider:
    """Get a provider instance by slug name."""
    cls = PROVIDERS.get(name.lower())
    if not cls:
        raise ValueError(f"Unknown provider: {name}. Available: {list(PROVIDERS.keys())}")
    return cls()


def list_providers() -> list[dict]:
    """List all registered providers with their metadata."""
    return [
        {
            "slug": slug,
            "name": cls.NAME,
            "description": cls.DESCRIPTION,
            "configured": cls.is_configured(),
        }
        for slug, cls in PROVIDERS.items()
    ]
