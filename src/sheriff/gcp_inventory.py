"""GCP Asset Inventory integration for Sheriff.

This module provides access to Google Cloud Asset Inventory for
querying compute instances across projects, folders, or organizations.

Architecture:
    Uses the Cloud Asset API's searchAllResources method to find
    Compute Engine instances matching specified criteria. Results
    are normalized to a consistent dictionary format for use by
    Sheriff's policy engine.

Use Cases:
    - Verify host exists in GCP Asset Inventory
    - List all instances with specific labels
    - Get instance details by hostname
    - Audit resources across organization

Configuration (settings.yaml):
    inventory:
      provider: gcp_asset
      gcp_asset:
        scope: "folders/123456789"  # or organizations/123456789
        asset_types:
          - "compute.googleapis.com/Instance"

Scope Formats:
    - projects/{PROJECT_ID}
    - folders/{FOLDER_ID}
    - organizations/{ORG_ID}

Example:
    >>> from gcp_inventory import GCPAssetInventory
    >>> inventory = GCPAssetInventory()
    >>> instances = inventory.list_instances({"env": "prod"})
    >>> for inst in instances:
    ...     print(f"{inst['name']} in {inst['location']}")
"""

from __future__ import annotations

import logging
from typing import Any

from config import SETTINGS
from google.cloud import asset_v1

# Module-level logger
_logger = logging.getLogger(__name__)


class GCPAssetInventory:
    """Query GCP Asset Inventory for compute resources.

    Provides methods to list, filter, and retrieve compute instances
    from Cloud Asset Inventory. Supports querying across projects,
    folders, or entire organizations.

    Thread Safety:
        The google.cloud.asset client is thread-safe. Multiple
        instances or concurrent method calls are supported.

    Attributes:
        scope: Asset Inventory scope (project/folder/organization).
        asset_types: List of asset types to query.
        client: Underlying Asset Service client.

    Raises:
        ValueError: If scope not configured in settings.yaml.
    """

    def __init__(self) -> None:
        """Initialize Asset Inventory client from configuration.

        Reads configuration from settings.yaml and creates the
        Asset Inventory client. Fails fast if required settings are missing.

        Required Configuration:
            inventory.gcp_asset.scope: Scope for asset search

        Optional Configuration:
            inventory.gcp_asset.asset_types: Asset types to search
                (default: ["compute.googleapis.com/Instance"])
        """
        inventory_config = SETTINGS.get("inventory", {}).get("gcp_asset", {})

        # Required configuration
        self.scope: str = inventory_config.get("scope", "")

        # Optional configuration with default
        self.asset_types: list[str] = inventory_config.get(
            "asset_types", ["compute.googleapis.com/Instance"]
        )

        # Fail-fast validation
        if not self.scope:
            raise ValueError(
                "GCP Asset Inventory scope must be configured in settings.yaml. "
                "Use format: 'folders/{ID}' or 'organizations/{ID}'"
            )

        # Initialize Asset Inventory client
        self.client = asset_v1.AssetServiceClient()

    def list_instances(self, filter_labels: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """List all compute instances in the configured scope.

        Queries Cloud Asset Inventory for all Compute Engine instances
        and optionally filters by labels. Results are normalized to
        dictionaries with consistent keys.

        Args:
            filter_labels: Optional dict of labels to filter by.
                All specified labels must match (AND logic).

        Returns:
            List of instance dictionaries with keys:
                - name: Instance name (not full resource name)
                - project: GCP project ID
                - location: Zone or region
                - labels: Dict of instance labels
                - state: Instance state (e.g., "RUNNING")
                - display_name: Human-readable display name

        Note:
            Cloud Asset Inventory may have slight delay (minutes)
            after resource creation or deletion.

        Example:
            >>> inventory.list_instances({"env": "prod", "tier": "web"})
            [{"name": "web-1", "project": "my-project", ...}]
        """
        request = asset_v1.SearchAllResourcesRequest(
            scope=self.scope,
            asset_types=self.asset_types,
        )

        resources: list[dict[str, Any]] = []

        try:
            for resource in self.client.search_all_resources(request=request):
                # Normalize resource to consistent format
                # Note: resource.labels is a MapComposite, convert to dict
                labels_dict = dict(resource.labels.items()) if resource.labels else {}

                instance_data: dict[str, Any] = {
                    "name": resource.name.split("/")[-1],  # Extract instance name
                    "project": resource.project,
                    "location": resource.location,
                    "labels": labels_dict,
                    "state": resource.state,
                    "display_name": resource.display_name,
                }

                # Apply label filter if specified
                if filter_labels:
                    labels: dict[str, str] = instance_data["labels"]
                    if all(labels.get(k) == v for k, v in filter_labels.items()):
                        resources.append(instance_data)
                else:
                    resources.append(instance_data)

        except Exception as e:
            _logger.error(f"Failed to list instances from Asset Inventory: {e}")
            # Return empty list rather than raising - allows graceful degradation

        _logger.debug(f"Found {len(resources)} instances in scope {self.scope}")
        return resources

    def verify_host(self, hostname: str) -> bool:
        """Check if a host exists in GCP Asset Inventory.

        Searches for an instance with the given hostname. Useful for
        validating that a resource exists before taking action.

        Args:
            hostname: Instance name to search for.

        Returns:
            True if instance found, False otherwise.

        Note:
            This performs a full scan of all instances. For frequent
            lookups, consider caching list_instances() results.
        """
        instances = self.list_instances()
        return any(instance["name"] == hostname for instance in instances)

    def get_instance(self, hostname: str) -> dict[str, Any] | None:
        """Get detailed instance information by hostname.

        Searches for and returns the first instance matching the
        given hostname.

        Args:
            hostname: Instance name to retrieve.

        Returns:
            Instance dictionary if found, None otherwise.

        Note:
            If multiple instances have the same name (across projects),
            only the first match is returned.
        """
        instances = self.list_instances()
        for instance in instances:
            if instance["name"] == hostname:
                return instance
        return None
