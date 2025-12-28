"""Google Cloud DNS management for Sheriff.

This module provides a high-level interface for managing DNS A records
in Google Cloud DNS. It abstracts the Cloud DNS API and handles:
- FQDN formatting with domain suffix
- Record creation, deletion, and replacement
- Atomic change sets for consistent updates

Architecture:
    CloudDNS instances are configured from settings.yaml and provide
    methods matching the DNS actions expected by Sheriff's policy engine.

Configuration (settings.yaml):
    dns:
      provider: cloud_dns
      cloud_dns:
        project: "gcp-project-id"
        managed_zone: "zone-name"
        domain_suffix: "example.com"
        default_ttl: 300
        nameserver: "1.1.1.2"

Cloud DNS Concepts:
    - Managed Zone: A container for DNS records for a domain
    - Resource Record Set (RRS): A collection of DNS records with same name/type
    - Change Set: Atomic batch of record additions/deletions

Example:
    >>> from cloud_dns import CloudDNS
    >>> dns = CloudDNS()
    >>> await dns.create_a("myserver", "10.0.0.1")
    >>> await dns.verify_a("myserver")
    True
    >>> await dns.delete_a("myserver")
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

from sheriff import api
from sheriff.config import SETTINGS

if TYPE_CHECKING:
    pass

# Module-level logger
_logger = logging.getLogger(__name__)


class CloudDNS:
    """Manage DNS A records in Google Cloud DNS.

    Provides create, read, update, delete operations for A records.
    All operations are idempotent where possible - creating an existing
    record or deleting a non-existent one will not raise errors.

    Async Implementation:
        Uses httpx via Sheriff's central async client for non-blocking
        I/O operations against the Google Cloud DNS REST API.

    Attributes:
        project: GCP project containing the managed zone.
        zone_name: Name of the Cloud DNS managed zone.
        domain_suffix: Domain suffix appended to hostnames (e.g., "prod.gcp.example.com").
        ttl: Default TTL in seconds for created records.
        nameserver: Public DNS resolver for verification (default: Cloudflare).
        base_url: Base URL for Cloud DNS API for this zone.

    Raises:
        ValueError: If project or managed_zone not configured in settings.yaml.
    """

    def __init__(self) -> None:
        """Initialize Cloud DNS client from configuration.

        Reads configuration from settings.yaml. Fails fast if required
        settings are missing.
        """
        dns_config = SETTINGS.get("dns", {}).get("cloud_dns", {})

        # Required configuration
        self.project: str = dns_config.get("project", "")
        self.zone_name: str = dns_config.get("managed_zone", "")

        # Optional configuration with sensible defaults
        self.domain_suffix: str = dns_config.get("domain_suffix", "")
        self.ttl: int = dns_config.get("default_ttl", 300)
        self.nameserver: str = dns_config.get("nameserver", "1.1.1.2")

        # Fail-fast validation - don't wait until first operation
        if not self.project or not self.zone_name:
            raise ValueError(
                "Cloud DNS project and managed_zone must be configured in settings.yaml. "
                "See documentation for configuration format."
            )

        self.base_url = f"https://dns.googleapis.com/dns/v1/projects/{self.project}/managedZones/{self.zone_name}"

    def _to_fqdn(self, hostname: str) -> str:
        """Convert hostname to fully-qualified domain name.

        Cloud DNS requires FQDNs with trailing dot. This method:
        1. Appends domain_suffix if configured
        2. Ensures trailing dot for DNS wire format

        Args:
            hostname: Short hostname (e.g., "myserver") or FQDN.

        Returns:
            FQDN with trailing dot (e.g., "myserver.prod.example.com.").
        """
        if self.domain_suffix:
            fqdn = f"{hostname}.{self.domain_suffix}"
        else:
            fqdn = hostname

        # DNS wire format requires trailing dot
        if not fqdn.endswith("."):
            fqdn = f"{fqdn}."

        return fqdn

    async def _get_client(self) -> httpx.AsyncClient:
        """Get the shared async client from API module."""
        return await api.CLIENTS.get_async_client()

    async def create_a(self, hostname: str, ip_address: str, replace: bool = False) -> bool:
        """Create an A record in Cloud DNS (async).

        Creates a new A record pointing hostname to ip_address.
        If replace=True, deletes any existing A record first using
        an atomic change set if possible (or delete-then-create).

        Args:
            hostname: Short hostname or FQDN to create.
            ip_address: IPv4 address for the A record.
            replace: If True, delete existing record before creating.

        Returns:
            True if record created successfully, False on error.
        """
        fqdn = self._to_fqdn(hostname)
        _logger.info(f"Creating A record: {fqdn} -> {ip_address}")

        client = await self._get_client()
        change: dict[str, Any] = {
            "additions": [
                {
                    "name": fqdn,
                    "type": "A",
                    "ttl": self.ttl,
                    "rrdatas": [ip_address],
                }
            ]
        }

        if replace:
            # Need to find existing record to delete it
            existing = await self._get_record(fqdn)
            if existing:
                change["deletions"] = [existing]
                _logger.debug(f"Queued deletion of existing record: {fqdn}")

        try:
            resp = await client.post(f"{self.base_url}/changes", json=change)
            resp.raise_for_status()
            _logger.info(f"Successfully created A record: {fqdn} -> {ip_address}")
            return True
        except httpx.HTTPStatusError as e:
            # 409 Conflict means record already exists (and replace=False)
            if e.response.status_code == 409:
                _logger.warning(f"Record {fqdn} already exists (use replace=True to overwrite)")
            else:
                _logger.error(f"Failed to create A record {fqdn}: {e.response.text}")
            return False
        except Exception as e:
            _logger.error(f"Failed to create A record {fqdn}: {e}")
            return False

    async def delete_a(self, hostname: str, ip_address: str | None = None) -> bool:
        """Delete an A record from Cloud DNS (async).

        Finds and deletes the A record for the given hostname.
        The ip_address parameter is accepted for interface compatibility
        but not currently used (all A records for the hostname are deleted).

        Args:
            hostname: Short hostname or FQDN to delete.
            ip_address: Optional IP address (unused, for interface compat).

        Returns:
            True if record deleted, False if not found or error.
        """
        fqdn = self._to_fqdn(hostname)
        _logger.info(f"Deleting A record: {fqdn}")

        existing = await self._get_record(fqdn)
        if not existing:
            _logger.warning(f"Record {fqdn} not found for deletion")
            return False

        change = {"deletions": [existing]}

        try:
            client = await self._get_client()
            resp = await client.post(f"{self.base_url}/changes", json=change)
            resp.raise_for_status()
            _logger.info(f"Successfully deleted A record: {fqdn}")
            return True
        except Exception as e:
            _logger.error(f"Failed to delete record {fqdn}: {e}")
            return False

    async def replace_a(self, hostname: str, ip_address: str) -> bool:
        """Replace an A record in Cloud DNS (async).

        Convenience method that deletes existing and creates new
        in a single atomic change set.

        Args:
            hostname: Short hostname or FQDN to replace.
            ip_address: New IPv4 address for the A record.

        Returns:
            True if replacement successful, False on error.
        """
        return await self.create_a(hostname, ip_address, replace=True)

    async def verify_a(self, hostname: str) -> bool:
        """Check if an A record exists in Cloud DNS (async).

        Queries the zone directly (not public DNS) to verify
        the record exists in Cloud DNS.

        Args:
            hostname: Short hostname or FQDN to check.

        Returns:
            True if A record exists, False otherwise.
        """
        fqdn = self._to_fqdn(hostname)
        record = await self._get_record(fqdn)
        return record is not None

    async def _get_record(self, fqdn: str) -> dict[str, Any] | None:
        """Fetch regular record set for FQDN (async helper)."""
        try:
            client = await self._get_client()
            resp = await client.get(f"{self.base_url}/rrsets", params={"name": fqdn, "type": "A"})
            resp.raise_for_status()
            data = resp.json()
            rrsets = data.get("rrsets", [])
            for rrs in rrsets:
                if rrs.get("name") == fqdn and rrs.get("type") == "A":
                    return rrs
        except Exception as e:
            _logger.debug(f"Error fetching record {fqdn}: {e}")
        return None
