"""Policy engine for Sheriff.

This module provides the core policy matching and action execution logic.
It implements a flexible filter system for matching GCP resources against
policy rules and dispatches appropriate actions.

Architecture:
    Policy Evaluation Pipeline:
    1. Resource received from Pub/Sub
    2. Resource matched against all policies (match_policy)
    3. Each filter evaluated using evaluate_filter
    4. Matching policies trigger action execution (execute_action)

Filter System:
    Filters use dot-notation for nested field access and support
    multiple operators for flexible matching:

    Presence:
        - "present": Field exists and is non-empty
        - "absent": Field missing or empty

    Comparison:
        - Simple value: Exact string match
        - "not_equals:value": Not equal
        - "regex:pattern": Regular expression match
        - ">N" / "<N": Numeric comparison

    Collection:
        - in: [list]: Value in allowed list
        - not_in: [list]: Value not in blocked list
        - "contains:value": List contains substring

Action System:
    Actions are registered in ACTION_HANDLERS and executed when
    policies match. Built-in actions:
    - alert: Slack notification + Cloud Logging
    - log: Cloud Logging only
    - stop: Stop compute instance
    - remediate: Auto-fix policy violations

Example Policy:
    policies:
      - name: no-external-ip
        resource: instance
        severity: high
        filters:
          - "networkInterfaces.0.accessConfigs": present
        actions:
          - alert

Example:
    >>> from policy_engine import match_policy, execute_action
    >>> if match_policy(resource, policy):
    ...     for action in policy['actions']:
    ...         execute_action(action, project, resource, policy)
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from sheriff import api

if TYPE_CHECKING:
    from collections.abc import Callable

# Module-level logger
_logger = logging.getLogger(__name__)


# =============================================================================
# Filter Evaluation Functions
# =============================================================================


def get_nested_value(resource: dict[str, Any], key: str) -> Any:
    """Extract a nested value from a dictionary using dot notation.

    Supports both dictionary key access and list index access,
    allowing paths like "networkInterfaces.0.accessConfigs.0.natIP".

    Algorithm:
        1. Split key by "." to get path segments
        2. For each segment:
           - If current is dict: get key
           - If current is list: parse int index and access
           - Otherwise: return None

    Args:
        resource: The resource dictionary to traverse.
        key: Dot-separated path (e.g., "labels.env", "disks.0.type").

    Returns:
        The value at the path, or None if any segment is missing.

    Examples:
        >>> get_nested_value({"a": {"b": 1}}, "a.b")
        1
        >>> get_nested_value({"items": [{"x": 1}]}, "items.0.x")
        1
        >>> get_nested_value({"a": 1}, "a.b.c")
        None
    """
    if key is None:
        return None

    parts = key.split(".")
    current: Any = resource

    for part in parts:
        if current is None:
            return None

        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            # Attempt to parse segment as list index
            try:
                index = int(part)
                current = current[index] if index < len(current) else None
            except (ValueError, IndexError):
                # Segment is not a valid index
                return None
        else:
            # Current value doesn't support subscripting
            return None

    return current


def evaluate_filter(resource: dict[str, Any], key: str, condition: Any) -> bool:
    """Evaluate a single filter condition against a resource field.

    This is the core comparison logic for policy matching. It supports
    multiple condition types for flexible policy definitions.

    Condition Types:
        Presence Checks:
            - "present": Field exists and is non-empty
            - "absent": Field is missing, None, or empty

        Exact Match:
            - Any value: Compared as string equality
            - Boolean: Direct comparison (YAML true/false)

        String Operators:
            - "regex:PATTERN": Python regex match
            - "not_equals:VALUE": String inequality
            - "contains:VALUE": Check if list contains substring

        Numeric Operators:
            - ">N": Greater than numeric comparison
            - "<N": Less than numeric comparison

        Collection Operators (dict conditions):
            - {"in": [...]: Value in allowed list
            - {"not_in": [...]: Value not in blocked list

    Args:
        resource: Dictionary to evaluate against.
        key: Dot-notation path to the field.
        condition: The condition to check (various types).

    Returns:
        True if condition matches, False otherwise.

    Examples:
        >>> evaluate_filter({"labels": {"env": "prod"}}, "labels.env", "present")
        True
        >>> evaluate_filter({"size": 100}, "size", ">50")
        True
        >>> evaluate_filter({"name": "prod-web-1"}, "name", "regex:^prod-")
        True
    """
    value = get_nested_value(resource, key)

    # -------------------------------------------------------------------------
    # Presence Operators
    # -------------------------------------------------------------------------
    if condition == "present":
        # Field exists and is non-empty
        if value is None:
            return False
        if isinstance(value, (list, dict, str)) and len(value) == 0:
            return False
        return True

    if condition == "absent":
        # Field missing, None, or empty
        if value is None:
            return True
        if isinstance(value, (list, dict, str)) and len(value) == 0:
            return True
        return False

    # -------------------------------------------------------------------------
    # Boolean Conditions
    # -------------------------------------------------------------------------
    if isinstance(condition, bool):
        return value == condition

    # -------------------------------------------------------------------------
    # String Conditions with Operators
    # -------------------------------------------------------------------------
    if isinstance(condition, str):
        # Regex match: "regex:^prod-.*"
        if condition.startswith("regex:"):
            pattern = condition[6:]
            if value is None:
                return False
            return bool(re.search(pattern, str(value)))

        # Not equals: "not_equals:prod"
        if condition.startswith("not_equals:"):
            compare_value = condition[11:]
            return str(value) != compare_value

        # Greater than: ">100"
        if condition.startswith(">"):
            try:
                threshold = float(condition[1:])
                return float(value) > threshold if value is not None else False
            except (ValueError, TypeError):
                return False

        # Less than: "<50"
        if condition.startswith("<"):
            try:
                threshold = float(condition[1:])
                return float(value) < threshold if value is not None else False
            except (ValueError, TypeError):
                return False

        # Contains: "contains:enable-oslogin"
        if condition.startswith("contains:"):
            search_value = condition[9:]
            if isinstance(value, list):
                # Check if any list item contains the search value
                return any(search_value in str(item) for item in value)
            if isinstance(value, dict):
                return search_value in value
            return False

        # Default: exact string equality
        return str(value) == condition

    # -------------------------------------------------------------------------
    # Dict Conditions (in/not_in operators)
    # -------------------------------------------------------------------------
    if isinstance(condition, dict):
        # In list: {"in": ["us-east4-a", "us-east4-b"]}
        if "in" in condition:
            allowed = condition["in"]
            return value in allowed if value is not None else False

        # Not in list: {"not_in": ["us-west1-a"]}
        if "not_in" in condition:
            disallowed = condition["not_in"]
            return value not in disallowed if value is not None else True

    # -------------------------------------------------------------------------
    # List Conditions (legacy format)
    # -------------------------------------------------------------------------
    if isinstance(condition, list):
        # Value must be in the provided list
        return value in condition

    # Default fallback: exact equality
    return value == condition


def match_policy(resource: dict[str, Any], policy: dict[str, Any]) -> bool:
    """Check if a resource matches all filters in a policy.

    Implements AND logic: ALL filters must match for the policy to match.
    Policies without filters match all resources of the correct type.

    Args:
        resource: The GCP resource dictionary.
        policy: Policy definition with optional "filters" key.

    Returns:
        True if all filters match (or no filters defined), False otherwise.

    Example:
        >>> policy = {
        ...     "filters": [
        ...         {"labels.env": "present"},
        ...         {"status": "RUNNING"}
        ...     ]
        ... }
        >>> match_policy({"labels": {"env": "prod"}, "status": "RUNNING"}, policy)
        True
    """
    filters = policy.get("filters", [])

    # No filters = matches all resources of this type
    if not filters:
        return True

    # Evaluate each filter (AND logic)
    for filter_item in filters:
        if isinstance(filter_item, dict):
            # Each filter is a dict with one key-value pair
            for key, condition in filter_item.items():
                if not evaluate_filter(resource, key, condition):
                    return False
        else:
            _logger.warning(f"Invalid filter format (expected dict): {filter_item}")
            return False

    return True


# =============================================================================
# Action Handlers
# =============================================================================


async def do_alert(
    project_resource: dict[str, Any],
    resource: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    """Send alert notification for policy violation (async).

    Creates a formatted Slack message and logs the violation to
    Cloud Logging with appropriate severity based on policy.

    Message Format:
        🚨 **Policy Violation**: no-external-ip
        • Resource: my-instance
        • Project: my-project
        • Severity: HIGH
        • Description: Block instances with public IP addresses

    Args:
        project_resource: Project context dictionary.
        resource: The violating resource.
        policy: The matched policy definition.
    """
    # Import here to avoid circular dependency
    from sheriff import log_event, record_metric, slack

    severity = policy.get("severity", "medium")
    severity_emoji = {"high": "🚨", "medium": "⚠️", "low": "ℹ️"}.get(severity, "⚠️")

    message = (
        f"{severity_emoji} **Policy Violation**: {policy['name']}\n"
        f"• Resource: `{resource.get('name', 'unknown')}`\n"
        f"• Project: `{project_resource.get('name', 'unknown')}`\n"
        f"• Severity: {severity.upper()}\n"
        f"• Description: {policy.get('description', 'N/A')}"
    )

    await slack(message)

    # Log with severity-appropriate level
    log_severity = "ERROR" if severity == "high" else "WARNING"
    log_event(
        {
            "event_type": "policy_violation",
            "policy": policy["name"],
            "severity": severity,
            "resource": resource.get("name"),
            "project": project_resource.get("name"),
        },
        severity=log_severity,
    )

    record_metric(
        "policy_violations",
        labels={"policy": policy["name"], "severity": severity},
    )


def do_log(
    project_resource: dict[str, Any],
    resource: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    """Log policy match without sending alert.

    Used for informational policies that should be tracked but
    don't require immediate attention.

    Args:
        project_resource: Project context dictionary.
        resource: The matched resource.
        policy: The matched policy definition.
    """
    from sheriff import log_event

    log_event(
        {
            "event_type": "policy_match",
            "policy": policy["name"],
            "resource": resource.get("name"),
            "project": project_resource.get("name"),
        }
    )


async def do_stop(
    project_resource: dict[str, Any],
    resource: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    """Stop a compute instance for policy enforcement (async).

    Uses the Compute Engine API to stop a running instance.
    Sends Slack notification and logs the action.

    WARNING: This action has production impact. Use with caution.

    Args:
        project_resource: Project context dictionary.
        resource: The instance resource to stop.
        policy: The triggering policy definition.
    """
    from sheriff import log_event, slack

    # Validate resource type
    if resource.get("kind") != "compute#instance":
        _logger.warning(f"Cannot stop non-instance resource: {resource.get('kind')}")
        return

    # Extract identifiers
    project = project_resource["name"]
    zone = resource["zone"].split("/")[-1]  # Extract zone name from URL
    instance = resource["name"]

    try:
        api.CLIENTS.compute.instances().stop(
            project=project, zone=zone, instance=instance
        ).execute()

        message = f"🛑 Stopped instance `{instance}` due to policy: {policy['name']}"
        await slack(message)

        log_event(
            {
                "event_type": "policy_enforcement",
                "action": "stop",
                "policy": policy["name"],
                "resource": instance,
            }
        )
    except Exception as e:
        _logger.error(f"Failed to stop instance {instance}: {e}")


async def do_remediate(
    project_resource: dict[str, Any],
    resource: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    """Auto-remediate policy violations (async).

    Automatically fixes detected policy violations. Currently supports:
    - Adding missing labels (via policy.remediation.add_labels)

    Policy Configuration:
        policies:
          - name: add-managed-label
            remediation:
              add_labels:
                managed-by: sheriff

    Args:
        project_resource: Project context dictionary.
        resource: The resource to remediate.
        policy: The policy with remediation configuration.
    """
    from sheriff import log_event, slack

    # Currently only supports compute instances
    if resource.get("kind") != "compute#instance":
        _logger.warning(f"Cannot remediate non-instance resource: {resource.get('kind')}")
        return

    remediation = policy.get("remediation", {})
    if "add_labels" not in remediation:
        _logger.debug(f"No remediation actions defined for policy: {policy['name']}")
        return

    # Extract identifiers
    project = project_resource["name"]
    zone = resource["zone"].split("/")[-1]
    instance = resource["name"]

    try:
        # Fetch current instance for label fingerprint
        current = (
            api.CLIENTS.compute.instances()
            .get(project=project, zone=zone, instance=instance)
            .execute()
        )

        # Merge existing labels with new ones
        labels = current.get("labels", {})
        labels.update(remediation["add_labels"])

        # Update labels (requires fingerprint for optimistic concurrency)
        api.CLIENTS.compute.instances().setLabels(
            project=project,
            zone=zone,
            instance=instance,
            body={
                "labels": labels,
                "labelFingerprint": current["labelFingerprint"],
            },
        ).execute()

        message = f"🔧 Remediated instance `{instance}`: added labels {remediation['add_labels']}"
        await slack(message)

        log_event(
            {
                "event_type": "policy_enforcement",
                "action": "remediate",
                "policy": policy["name"],
                "resource": instance,
                "labels_added": remediation["add_labels"],
            }
        )

    except Exception as e:
        _logger.error(f"Failed to remediate instance {instance}: {e}")


# =============================================================================
# Action Handler Registry
# =============================================================================

#: Registry mapping action names to handler functions (async coroutines).
#: Add new actions here to extend the policy system.
ACTION_HANDLERS: dict[str, Callable[..., Any]] = {
    "alert": do_alert,
    "log": do_log,
    "stop": do_stop,
    "remediate": do_remediate,
}


async def execute_action(
    action: str,
    project_resource: dict[str, Any],
    resource: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    """Execute a policy action by name (async).

    Looks up the action in ACTION_HANDLERS and invokes it with
    the resource context. Unknown actions are logged but don't
    raise errors (may be handled elsewhere).

    Args:
        action: Action name (e.g., "alert", "log", "stop").
        project_resource: Project context dictionary.
        resource: The resource being processed.
        policy: The matched policy definition.

    Note:
        Actions "dns" and "inventory" are handled by sheriff.py
        directly and will log at debug level here.
    """
    handler = ACTION_HANDLERS.get(action)

    if handler:
        try:
            await handler(project_resource, resource, policy)
        except Exception as e:
            _logger.error(f"Failed to execute action '{action}': {e}")
    else:
        # Action not in engine - might be handled by sheriff.py (dns, inventory)
        _logger.debug(f"Action '{action}' not handled by policy engine")
