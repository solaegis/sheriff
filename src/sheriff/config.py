"""Configuration loader for Sheriff.

This module provides centralized configuration loading from YAML files.
Configuration is loaded once at module import and cached in module-level
constants for performance.

Configuration Files:
    settings.yaml: Runtime configuration including GCP settings, DNS config,
        inventory settings, and alerting configuration.

    policies.yaml: Policy definitions that determine how resources are
        matched and what actions to take.

Thread Safety:
    SETTINGS and POLICIES are read-only after module initialization,
    making them inherently thread-safe for read access.

Environment Variables:
    Configuration values can reference environment variables using
    standard YAML syntax or Python string substitution after load.

Example:
    >>> from config import SETTINGS, POLICIES
    >>> dns_project = SETTINGS.get('dns', {}).get('cloud_dns', {}).get('project')
    >>> for policy in POLICIES:
    ...     print(policy['name'])
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

# Module-level logger
_logger = logging.getLogger(__name__)

# Resolve the directory containing this module (for relative file paths)
_MODULE_DIR = Path(__file__).parent


def load_settings() -> dict[str, Any]:
    """Load runtime settings from settings.yaml.

    Settings control Sheriff's behavior including:
    - Pub/Sub subscription configuration
    - DNS provider settings (Cloud DNS)
    - Inventory provider settings (GCP Asset Inventory)
    - Alerting configuration (Slack webhooks)
    - Retry and batch size parameters

    Returns:
        Dictionary containing all settings, or empty dict if file
        not found. Missing file is not an error (allows defaults).

    Raises:
        yaml.YAMLError: If settings.yaml contains invalid YAML.

    Note:
        Uses yaml.safe_load() to prevent arbitrary code execution
        from untrusted YAML content.
    """
    settings_path = _MODULE_DIR / "settings.yaml"

    if not settings_path.exists():
        _logger.warning("settings.yaml not found, using empty configuration")
        return {}

    with settings_path.open() as f:
        settings = yaml.safe_load(f)
        return settings or {}


def load_policies() -> list[dict[str, Any]]:
    """Load policy definitions from policies.yaml.

    Policies define rules for matching GCP resources and the actions
    to take when a match occurs. Each policy contains:
    - name: Unique identifier for the policy
    - resource: GCP resource type to match (e.g., "instance")
    - filters: Conditions that must match (optional)
    - actions: List of actions to execute on match
    - severity: Policy violation severity level (optional)
    - description: Human-readable policy description (optional)

    Returns:
        List of policy dictionaries, or empty list if file not found.

    Raises:
        yaml.YAMLError: If policies.yaml contains invalid YAML.
        KeyError: If 'policies' key is missing (returns empty list).

    Example policies.yaml:
        policies:
          - name: no-external-ip
            resource: instance
            severity: high
            filters:
              - "networkInterfaces.0.accessConfigs": present
            actions:
              - alert
    """
    policies_path = _MODULE_DIR / "policies.yaml"

    if not policies_path.exists():
        _logger.warning("policies.yaml not found, no policies loaded")
        return []

    with policies_path.open() as f:
        data = yaml.safe_load(f)
        policies = data.get("policies", []) if data else []
        _logger.info(f"Loaded {len(policies)} policies from policies.yaml")
        return policies


# =============================================================================
# Module-Level Constants
# =============================================================================
# These are loaded once at import time and cached for the lifetime of
# the process. Any changes to the YAML files require a restart.

#: Runtime configuration loaded from settings.yaml
SETTINGS: dict[str, Any] = load_settings()

#: Policy definitions loaded from policies.yaml
POLICIES: list[dict[str, Any]] = load_policies()
