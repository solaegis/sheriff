"""Async GCP API client management.

This module provides async-compatible wrappers for Google Cloud API clients.
It uses httpx for async HTTP operations and provides both sync and async
interfaces for GCP services.

Architecture:
    - AsyncClients: Container for async-compatible API clients
    - Uses google-auth for authentication
    - httpx for async HTTP transport
    - google.cloud.* clients for thread-safe operations

Thread Safety:
    The google.cloud.* clients (datastore, pubsub) are inherently thread-safe.
    For discovery-based APIs, we now use httpx which is also thread-safe
    and async-compatible.

Example:
    >>> from api import CLIENTS
    >>> # Sync usage (compatibility)
    >>> instances = CLIENTS.compute.instances().list(project='my-project').execute()
    >>> # Async clients available for modern usage
    >>> async with CLIENTS.http_client as client:
    ...     response = await client.get(url)
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Generator
from typing import Any

import google.auth
import google.auth.transport.requests
import google.cloud.pubsub_v1 as pubsub
import google.cloud.resourcemanager_v3 as resource_manager
import httpx
from google.cloud import datastore
from googleapiclient import discovery, errors

# Module-level logger
_logger = logging.getLogger(__name__)

# Global credentials - initialized once
_credentials, _project = google.auth.default(
    scopes=["https://www.googleapis.com/auth/cloud-platform"]
)


def resource_iterator(
    next_page_function: Callable[[str | None], Any],
) -> Generator[Any, None, None]:
    """Iterate through paginated Google API responses.

    Google APIs return results in pages with tokens for continuation.
    This generator abstracts pagination, yielding individual resources
    across all pages until exhausted.

    Args:
        next_page_function: Callable that accepts a page token and returns
            an API request object with execute() method.

    Yields:
        Individual resource items from the paginated response.
    """
    next_page_token = None
    more_results = True

    while more_results:
        try:
            resource_response = next_page_function(next_page_token).execute()
        except errors.HttpError:
            _logger.debug("Skipping resources due to API error", exc_info=True)
            return

        for items_field in ["items", "rrsets", "managedZones"]:
            items = resource_response.get(items_field, {})

            if items and isinstance(items, dict):
                for item in items.items():
                    yield item

            if items and isinstance(items, list):
                for item in items:
                    yield item

        if "nextPageToken" in resource_response:
            next_page_token = resource_response["nextPageToken"]
        else:
            more_results = False


class Clients:
    """Centralized container for all GCP API clients.

    Provides both sync (discovery-based) and async-compatible clients.
    The sync clients use google-api-python-client for backward compatibility.
    Async operations use httpx with Google auth.

    Sync Clients (discovery-based):
        - compute: Compute Engine API
        - dns: Cloud DNS API
        - metrics: Cloud Monitoring API
        - iam: Cloud Resource Manager API

    Thread-Safe Clients:
        - datastore: Cloud Datastore
        - crm: Resource Manager Projects
        - subscriber: Pub/Sub subscriber

    Async Support:
        - http_client: httpx.AsyncClient for custom async requests
        - get_auth_headers(): Get authorization headers for manual requests
    """

    def __init__(self) -> None:
        """Initialize API clients.

        Creates discovery-based clients for sync operations and
        prepares auth for async operations.
        """
        # Refresh credentials
        request = google.auth.transport.requests.Request()
        _credentials.refresh(request)

        # Discovery-based sync clients
        self._compute = discovery.build(
            "compute", "v1", credentials=_credentials, cache_discovery=False
        )
        self._dns = discovery.build("dns", "v1", credentials=_credentials, cache_discovery=False)
        self._metrics = discovery.build(
            "monitoring", "v3", credentials=_credentials, cache_discovery=False
        )
        self._iam = discovery.build(
            "cloudresourcemanager", "v1", credentials=_credentials, cache_discovery=False
        )

        # Thread-safe cloud clients
        self.datastore = datastore.Client()
        self.crm = resource_manager.ProjectsClient()
        self.subscriber = pubsub.SubscriberClient()

        # Async HTTP client (lazy initialized)
        self._async_http_client: httpx.AsyncClient | None = None

    @property
    def compute(self) -> Any:
        """Compute Engine API client."""
        return self._compute

    @property
    def dns(self) -> Any:
        """Cloud DNS API client."""
        return self._dns

    @property
    def metrics(self) -> Any:
        """Cloud Monitoring API client."""
        return self._metrics

    @property
    def iam(self) -> Any:
        """Cloud Resource Manager API client."""
        return self._iam

    def get_auth_headers(self) -> dict[str, str]:
        """Get authorization headers for HTTP requests.

        Refreshes credentials if needed and returns headers suitable
        for authenticated API requests.

        Returns:
            Dict with Authorization header.
        """
        if not _credentials.valid:
            request = google.auth.transport.requests.Request()
            _credentials.refresh(request)

        return {"Authorization": f"Bearer {_credentials.token}"}

    async def get_async_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client.

        Returns a configured httpx.AsyncClient for async operations.
        The client is reused across calls for connection pooling.

        Returns:
            Configured async HTTP client.
        """
        if self._async_http_client is None or self._async_http_client.is_closed:
            self._async_http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0),
                headers=self.get_auth_headers(),
            )
        return self._async_http_client

    async def async_get(self, url: str) -> dict[str, Any]:
        """Perform async GET request with authentication.

        Args:
            url: URL to fetch.

        Returns:
            JSON response as dictionary.

        Raises:
            httpx.HTTPError: On request failure.
        """
        client = await self.get_async_client()
        # Refresh headers in case credentials expired
        client.headers.update(self.get_auth_headers())
        response = await client.get(url)
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        """Close async clients and release resources."""
        if self._async_http_client and not self._async_http_client.is_closed:
            await self._async_http_client.aclose()


# Module-level singleton
CLIENTS = Clients()
