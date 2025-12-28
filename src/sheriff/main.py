#!/usr/bin/env python
"""Sheriff - GCP Resource Life-Cycle Management.

Sheriff is a policy-driven automation framework that monitors GCP Pub/Sub
event streams and applies configurable policies to enforce security,
compliance, and operational standards.

Architecture:
    1. Pub/Sub Consumer: Pulls audit log events from GCP Pub/Sub
    2. Message Parser: Extracts resource info from v1/v2 log formats
    3. Policy Engine: Matches resources against YAML-defined policies
    4. Action Dispatcher: Executes configured actions (DNS, alerts, etc.)

Async Model:
    - Main event loop: Pulls messages from Pub/Sub
    - Async tasks: Process messages concurrently (bounded by semaphore)
    - Graceful shutdown: Waits for in-flight tasks on SIGTERM/SIGINT

Data Persistence:
    - Datastore: Stores resource state for deletion handling
    - Cloud Logging: Structured event logging
    - Cloud Monitoring: Custom metrics for observability

Configuration:
    - settings.yaml: Runtime configuration (Pub/Sub, DNS, etc.)
    - policies.yaml: Policy definitions and actions

Usage:
    $ sheriff
    $ python -m sheriff

Environment Variables:
    SLACK_WEBHOOK: Webhook URL for Slack notifications
    GCP_PROJECT: Default GCP project for metrics (optional)
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import signal
import time
from typing import Any

import google.auth
import google.cloud.logging
import google.cloud.monitoring_v3
import httpx
from google.cloud import datastore
from googleapiclient import discovery, errors

from sheriff import api, policy_engine
from sheriff.cloud_dns import CloudDNS
from sheriff.config import POLICIES, SETTINGS

# =============================================================================
# Module Constants and Configuration
# =============================================================================

# Set of valid resource types from loaded policies (populated at startup)
VALID_TYPES: set[str] = set()

# Pub/Sub configuration with sensible defaults
_sheriff_config = SETTINGS.get("sheriff", {})
_pubsub_config = _sheriff_config.get("pubsub", {})

PUBSUB_SCOPES = _pubsub_config.get("scopes", ["https://www.googleapis.com/auth/cloud-platform"])
NUM_RETRIES = _sheriff_config.get("retries", 3)  # Exponential backoff retries
BATCH_SIZE = _pubsub_config.get("batch_size", 10)  # Messages per pull
MAX_CONCURRENT_TASKS = _sheriff_config.get("max_concurrent_tasks", 20)  # Async concurrency limit

_filters_config = _sheriff_config.get("filters", {})
PROJECT_PREFIX = _filters_config.get("project_prefix", "pcln-pl")
SANDBOX_PATTERN = _filters_config.get("sandbox_pattern", ".*-sandbox")
ALLOWED_NETWORKS = _filters_config.get("allowed_networks", ["pl-nonprod", "pl-prod"])

# Configure logging format to include thread name (crucial for debugging)
logging.basicConfig(
    level=logging.INFO,
    format="(%(threadName)-10s) [%(levelname)s] %(message)s",
)

# Module-level logger
_logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================


class CreatedResource(datastore.Entity):
    """Store resource data upon creation and updates.

    When a delete event is received we won't have resource data anymore so it's
    not possible to delete the A record. This stores the resource in datastore
    Need the resource upon resource deletion, so save the created resource
    keyed by the string 'project_id:resource_type:resource_id'.
    """

    KIND = "CreatedResource"

    def __init__(
        self, entity_id: str, project_id: str, resource_name: str, resource_string: str
    ) -> None:
        """Save resource_name and a_records.

        Args:
            entity_id: should be '<project_id>:<resource_type>:<resource_id>'.
            project_id: id of the project.
            resource_name: name of the resource.
            resource_string: json (as string) of the resource.
        """
        super().__init__(
            key=api.CLIENTS.datastore.key(CreatedResource.KIND, entity_id),
            exclude_from_indexes=["resource_string"],
        )
        self.update(
            {
                "project_id": project_id,
                "resource_name": resource_name,
                "resource_string": resource_string,
            }
        )

    @classmethod
    def get_by_id(cls, entity_id: str) -> CreatedResource | None:
        """Lookup a CreatedResource by id.

        Args:
            entity_id: string id of the entity.

        Returns:
            The found CreatedResource or None.
        """
        entity = api.CLIENTS.datastore.get(
            api.CLIENTS.datastore.key(CreatedResource.KIND, entity_id)
        )
        if entity:
            return CreatedResource(
                entity_id, entity["project_id"], entity["resource_name"], entity["resource_string"]
            )
        else:
            return None

    def put(self):
        """Saves entity in datastore."""
        res = None
        for i in range(NUM_RETRIES):
            try:
                res = api.CLIENTS.datastore.put(self)
                break
            except Exception:
                time.sleep(2**i)
        return res

    def delete(self):
        """Deletes entity from datastore."""
        res = None
        for i in range(NUM_RETRIES):
            try:
                res = api.CLIENTS.datastore.delete(self.key)
                break
            except Exception:
                time.sleep(2**i)
        return res


# =============================================================================
# Core Functions
# =============================================================================


async def slack(message: str) -> None:
    """Send a notification message to Slack asynchronously.

    Sends formatted messages to a configured Slack channel via webhook.
    Gracefully handles missing webhook configuration by logging only.

    Args:
        message: The message text to send. Supports Slack markdown.

    Environment:
        SLACK_WEBHOOK: Required. The Slack incoming webhook URL.

    Configuration (settings.yaml):
        sheriff.slack.channel: Target channel (default: #gcp-info)
        sheriff.slack.username: Bot username (default: Sheriff)
    """
    _logger.info(f"slack-message: {message}")

    webhook_url = os.environ.get("SLACK_WEBHOOK")
    if not webhook_url:
        _logger.warning("SLACK_WEBHOOK not set, skipping notification")
        return

    slack_settings = SETTINGS.get("sheriff", {}).get("slack", {})
    payload = {
        "channel": slack_settings.get("channel", "#gcp-info"),
        "username": slack_settings.get("username", "Sheriff"),
        "text": message,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, data={"payload": json.dumps(payload)})
            _logger.info(f"Slack response: HTTP {resp.status_code}")
    except Exception as e:
        _logger.error(f"Failed to send Slack message: {e}")


def log_event(message_data: Any, severity: str = "INFO") -> None:
    """Send structured log event to Google Cloud Logging."""
    # This automatically includes trace/resource data when run in GCP
    logging.log(getattr(logging, severity.upper(), logging.INFO), message_data)


def record_metric(metric_type: str, value: int = 1, labels: dict[str, str] | None = None) -> None:
    """Record a custom metric in Google Cloud Monitoring."""
    client = google.cloud.monitoring_v3.MetricServiceClient()
    default_project = (
        SETTINGS.get("sheriff", {}).get("gcp", {}).get("default_project", "pcln-pl-infra-prod")
    )
    project_name = f"projects/{os.environ.get('GCP_PROJECT', default_project)}"

    series = google.cloud.monitoring_v3.TimeSeries()
    series.metric.type = f"custom.googleapis.com/sheriff/{metric_type}"
    if labels:
        series.metric.labels.update(labels)

    series.resource.type = "global"

    now = time.time()
    seconds = int(now)
    nanos = int((now - seconds) * 10**9)
    interval = google.cloud.monitoring_v3.TimeInterval(
        {"end_time": {"seconds": seconds, "nanos": nanos}}
    )
    point = google.cloud.monitoring_v3.Point(
        {"interval": interval, "value": {"int64_value": value}}
    )
    series.points = [point]

    try:
        client.create_time_series(name=project_name, time_series=[series])
    except Exception as e:
        logging.error(f"Failed to record metric {metric_type}: {e}")


def set_labels(project, zone, instance, labels):
    # Refresh resource in case it has been changed
    global CREDENTIALS
    # Construct a new instance of API client because httplib2 is not thread safe
    compute = discovery.build("compute", "v1", credentials=CREDENTIALS)

    instances = (
        compute.instances()
        .get(project=project, zone=zone, instance=instance)
        .execute(num_retries=NUM_RETRIES)
    )
    for key, value in labels.items():
        instances["labels"][key] = value
    compute.instances().setLabels(
        project=project,
        zone=zone,
        instance=instance,
        body={"labels": instances["labels"], "labelFingerprint": instances["labelFingerprint"]},
    ).execute(num_retries=NUM_RETRIES)


async def do_dns(project_resource, resource, event_subtype=None):
    """Update PCLN DNS with instances from GCP (async)."""

    def get_dns_names(project_resource, resource):
        """Get the DNS Names of a resource.

        Args:
            project_resource: The resource owning project.
            resource: GCE resource object (like an instance or forwarding rule).

        Returns:
            A tuple of three strings: the DNS name for the resource, the
            external DNS zone name and the internal DNS zone name.
        """
        zone_dns_name = None
        if "metadata" in resource and "items" in resource["metadata"]:
            for item in resource["metadata"]["items"]:
                if item["key"] == "domain":
                    zone_dns_name = item["value"]
        if not zone_dns_name:
            if "items" in project_resource.get("commonInstanceMetadata"):
                for item in project_resource["commonInstanceMetadata"]["items"]:
                    if item["key"] == "domain":
                        zone_dns_name = item["value"]
        if not zone_dns_name:
            logging.info(
                "Unable to get DNS name for {}. Project {} has no domain defined".format(
                    resource["name"], project_resource["name"]
                )
            )
            return None
        if (
            resource["kind"] == "compute#forwardingRule"
            and resource["loadBalancingScheme"] == "INTERNAL"
        ):
            # Our filters are not sophisticated enough to handle the following logic.
            # Hard coding for now.
            if resource["network"].split("/")[-1] in ALLOWED_NETWORKS:
                resource_name = resource["backendService"].split("/")[-1]
            else:
                return None
        else:
            resource_name = resource["name"]
        return f"{resource_name}.{zone_dns_name}"

    def get_zone_ip(project_resource, resource):
        """Get Cloud DNS zone name and list of dns name and IPs for a resource.

        Args:
            project_resource: GCP project resource.
            resource: GCE resource.

        Returns:
            A tuple containing zone_name and list of tuples of dns_name and ip
            associated with a resource.
            For example:
            (zone_name, [(dns_name, [ip,ip]), (dns_name, [ip,ip])])
        """
        a_records: list[tuple[str, list[str]]] = []
        dns_name = get_dns_names(project_resource, resource)
        if not dns_name:
            return a_records

        if resource["kind"] == "compute#instance":
            # Process all IP addresses, but the first IP address is considered the
            # primary doesn't have an interface prefixed. for example, an instance
            # with three interfaces will have the dns names:
            #
            #         instance-1.mydns.com
            #    nic1.instance-1.mydns.com
            #    nic2.instance-1.mydns.com
            for i, interface in enumerate(resource["networkInterfaces"]):
                if i == 0:
                    a_records.append((dns_name, [interface["networkIP"]]))
                else:
                    a_records.append(("nic%d.%s" % (i, dns_name), [interface["networkIP"]]))
        elif resource["kind"] == "compute#forwardingRule":
            a_records.append((dns_name, [resource["IPAddress"]]))
        return a_records

    action = "do_dns"
    if event_subtype and event_subtype.split(".")[-1] not in [
        "insert",
        "delete",
        "start",
        "stop",
        "prempted",
        "guestTerminate",
    ]:
        logging.info(f"{action}: event_subtype {event_subtype} not applicable")
        return
    a_records = get_zone_ip(project_resource, resource)

    status = True
    logging.debug("do_dns for %s", resource["name"])

    dns_provider = SETTINGS.get("dns", {}).get("provider", "cloud_dns")
    if dns_provider != "cloud_dns":
        logging.error(f"Unsupported DNS provider: {dns_provider}. Only 'cloud_dns' is supported.")
        return

    dns_client = CloudDNS()

    for record in a_records:
        hostname = record[0]
        ip_address = record[1][0]
        if "deleted" in resource or ("status" in resource and resource["status"] != "RUNNING"):
            logging.info("%s: deleting %s with ip %s", action, hostname, ip_address)
            status = await dns_client.delete_a(hostname, ip_address)
        else:
            logging.info("%s: replacing %s with %s ip", action, hostname, ip_address)
            status = await dns_client.replace_a(hostname, ip_address)

    if status is not True:
        message = "do_dns failed for {}".format(resource["name"])
        logging.error(message)
        await slack(message)

    return


def do_inventory(resource, event_subtype=None):
    """Log inventory events to GCP (GCP Asset Inventory is the source of truth)."""
    action = "do_inventory"
    if event_subtype and event_subtype.split(".")[-1] not in [
        "insert",
        "delete",
        "start",
        "stop",
        "prempted",
        "guestTerminate",
        "setMetadata",
    ]:
        logging.info(f"{action}: event_subtype {event_subtype} not applicable")
        return
    if resource.get("kind") != "compute#instance":
        logging.info(
            "{}: resource {} is not supported because it is not a compute instance".format(
                action, resource["name"]
            )
        )
        return

    # GCP Asset Inventory is the source of truth - just log the event
    if "deleted" in resource or resource["status"] != "RUNNING":
        log_event({"inventory_event": "instance_deleted", "resource": resource["name"]})
        record_metric("inventory_events", labels={"type": "delete"})
    else:
        log_event({"inventory_event": "instance_created", "resource": resource["name"]})
        record_metric("inventory_events", labels={"type": "create"})
    return


def get_value(resource, key):
    if key is not None:
        parts = key.split(".", 1)
        if len(parts) > 1:
            return get_value(resource[parts[0]], parts[1])
        else:
            return resource[key]
    else:
        return None


def match(resource, filters):
    """Match given resources against give filters."""
    matched = False
    for filter_item in filters:
        # Only supports simple key = value matching for now
        key, operation = list(filter_item.items())[0]

        try:
            item = get_value(resource, key)
        except Exception:
            item = None

        if item is not None:
            if operation == "absent" or (operation != "present" and operation != item):
                return False
            else:
                matched = True
        else:
            logging.info(f"match: {key} not found")
            if operation != "absent":
                return False
            else:
                matched = True
    return matched


def retrieve_resource(project, message_payload):
    """Store reource created/updated.

    Args:
        project: Name of project owning the resource.
        # resource_type: Type of the resource like "instance" or "forwardingRule".
        # resource_id: unique id of the resource.
        message_payload: pubsub message payload.
    """
    operation_reference = message_payload["operation"]
    operation_name = operation_reference["name"]

    operation = None
    try:
        if "global" in operation_reference:
            operation = (
                api.CLIENTS.compute.globalOperations()
                .get(operation=operation_name, project=project)
                .execute()
            )
        elif "region" in operation_reference:
            operation = (
                api.CLIENTS.compute.regionOperations()
                .get(
                    operation=operation_name, project=project, region=operation_reference["region"]
                )
                .execute()
            )
        elif "zone" in operation_reference:
            operation = (
                api.CLIENTS.compute.zoneOperations()
                .get(operation=operation_name, project=project, zone=operation_reference["zone"])
                .execute()
            )
    except errors.HttpError as error:
        if error.resp.status == 404:
            # Don't raise exception on 404, some operations like GAE
            # Flexible operations can't be retrieved.
            logging.debug("unable to retrieve operation %s/%s", project, operation_name)
            return
        else:
            raise

    # Lookup the resource the operation was performed on
    if not operation:
        return None
    resource_url = operation["targetLink"]
    response, content = api.CLIENTS.compute._http.request(resource_url)
    if (response.status < 200) or (response.status >= 300):
        logging.error(
            "unable %s to get resource from url %s: %s", response.status, resource_url, content
        )
        return
    resource = json.loads(content)
    return resource


def parse_audit_log_message(message_body):
    """Parse out useful values from the received message body.

    Handles both logs v1 and v2 format messages.

    Args:
        message_body: The received message.

    Returns:
        Tuple of (resource_type, resource_id, project, message_payload)
        where the resource_type is the type of the resource like 'instance'
        or 'forwardingRule', resource_id is a unique identifier of the
        resource, project is id of the project owning the resource and
        message_payload is the decoded and parsed message body.
    """
    message_string = base64.b64decode(str(message_body["data"]))
    logging.debug("decoded message %s", message_string)
    message = json.loads(message_string)

    attrs = message_body["attributes"]

    resource_type = attrs.get("compute.googleapis.com/resource_type", None)
    # this is V1 format if we have a resource type
    if resource_type:
        message_payload = message["structPayload"]
        project = message["metadata"]["projectId"]
        resource_id = attrs["compute.googleapis.com/resource_id"]
    else:
        message_payload = message["jsonPayload"]
        project = message["resource"]["labels"]["project_id"]
        resource_id = message["labels"]["compute.googleapis.com/resource_id"]

    resource_type = message_payload["resource"]["type"]
    return resource_type, resource_id, project, message_payload


async def match_actions(
    entity_id: str,
    stored_resource: CreatedResource,
    project_resource: dict[str, Any],
    resource: dict[str, Any],
    resource_type: str,
    event_subtype: str,
) -> None:
    """Process resource against policies and execute matching actions.

    Iterates through all loaded policies, matches applicable ones against
    the resource, and executes the configured actions for matches.

    Args:
        entity_id: Unique resource identifier (project:type:id).
        stored_resource: The stored resource entity.
        project_resource: Project metadata dict.
        resource: The GCP resource dict.
        resource_type: Resource type string.
        event_subtype: Event subtype (insert, delete, etc.).
    """
    log_event({"project_resource": project_resource, "resource": resource})
    matched = False

    for policy in POLICIES:
        if resource_type != policy["resource"]:
            continue

        logging.debug(f"Evaluating policy: {policy['name']}")

        # Use enhanced policy matching from policy_engine
        if policy_engine.match_policy(resource, policy):
            matched = True
            log_event(
                {
                    "policy_match": policy["name"],
                    "actions": policy["actions"],
                    "resource": resource.get("name"),
                }
            )
            record_metric("policy_match_count", labels={"policy": policy["name"]})

            for action in policy["actions"]:
                # Core operational actions handled here
                if action == "inventory":
                    do_inventory(resource, event_subtype)
                elif action == "dns":
                    await do_dns(project_resource, resource, event_subtype)
                else:
                    # Delegate to policy engine for other actions (alert, log, stop, etc.)
                    await policy_engine.execute_action(action, project_resource, resource, policy)

    if not matched:
        logging.info(f"Ignoring {entity_id} since it does not match any policies")

    if "deleted" in resource:
        stored_resource.delete()


async def process(message_body: dict[str, Any]) -> None:
    """Process messages from Google PubSub (async).

    Parses audit log messages and schedules async policy evaluation.
    """
    global PROJECT_RESOURCE_MAP

    message_id = message_body["messageId"]
    (resource_type, resource_id, project, message_payload) = parse_audit_log_message(message_body)

    errors = message_payload.get("error", ())
    if resource_type not in VALID_TYPES or errors:
        logging.debug("message %s for %s not interesting for Sheriff", message_id, resource_type)
        return

    if re.search(SANDBOX_PATTERN, project) is not None:
        logging.debug(
            "message %s for %s is for a sandbox and not interesting for Sheriff",
            message_id,
            resource_type,
        )
        return

    event_type = message_payload["event_type"]
    if event_type != "GCE_OPERATION_DONE":
        logging.debug("message %s is not a completed operation", message_id)
        return

    event_subtype = message_payload["event_subtype"]
    entity_id = f"{project}:{resource_type}:{resource_id}"
    logging.info(f"{event_subtype} - {entity_id}")

    resource = None
    if not event_subtype.endswith(".delete"):
        for i in range(NUM_RETRIES):
            try:
                resource = retrieve_resource(project, message_payload)
                break
            except Exception:
                time.sleep(2**i)

    # Update project resource when change is detected
    if resource_type == "gce_project":
        project_resource = retrieve_resource(project, message_payload)
        if project_resource:
            PROJECT_RESOURCE_MAP[project] = project_resource
    elif project not in PROJECT_RESOURCE_MAP:
        try:
            project_resource = api.CLIENTS.compute.projects().get(project=project).execute()
            PROJECT_RESOURCE_MAP[project] = project_resource
        except Exception:
            message = f"process: Unable to find project {project} while processing {entity_id}"
            await slack(message)
            logging.error(message, exc_info=True)
            return
    else:
        project_resource = PROJECT_RESOURCE_MAP[project]

    if resource:
        logging.debug("adding stored resource with id %s", entity_id)
        resource_name = message_payload["resource"]["name"]
        stored_resource = CreatedResource(
            entity_id=entity_id,
            project_id=project,
            resource_name=resource_name,
            resource_string=json.dumps(resource),
        )
        stored_resource.put()
    else:
        resource_data = CreatedResource.get_by_id(entity_id)
        if resource_data is None:
            logging.info(f"Resource {entity_id} does not exist in datastore")
            return
        else:
            stored_resource = resource_data
            resource = json.loads(stored_resource["resource_string"])
            if event_subtype.endswith(".delete"):
                resource["deleted"] = True

    # Create async task for policy matching (non-blocking)
    # The task will be managed by the semaphore in the main loop
    asyncio.create_task(
        match_actions(
            entity_id, stored_resource, project_resource, resource, resource_type, event_subtype
        )
    )


async def populate_datastore() -> None:
    """Populate datastore with existing resources (async, not currently in use)."""
    global PROJECT_RESOURCE_MAP

    for project_data in api.CLIENTS.crm.list_projects():
        project = project_data.project_id
        if not project.startswith(PROJECT_PREFIX):
            continue
        try:
            project_resource = (
                api.CLIENTS.compute.projects().get(project=project).execute(num_retries=NUM_RETRIES)
            )
            PROJECT_RESOURCE_MAP[project] = project_resource
        except Exception:
            message = f"populate_datastore: Unable to retrieve project data for {project}"
            await slack(message)
            logging.error(message, exc_info=True)
            continue

        resp = (
            api.CLIENTS.compute.instances()
            .aggregatedList(project=project)
            .execute(num_retries=NUM_RETRIES)
        )
        for zone in resp["items"].keys():
            if "instances" in resp["items"][zone]:
                for resource in resp["items"][zone]["instances"]:
                    resource_name = resource["name"]
                    resource_type = resource["kind"].split("#")[-1]
                    resource_id = resource["id"]
                    entity_id = f"{project}:{resource_type}:{resource_id}"

                    logging.info(f"Processing {entity_id}")
                    stored_resource = CreatedResource(
                        entity_id=entity_id,
                        project_id=project,
                        resource_name=resource_name,
                        resource_string=json.dumps(resource),
                    )
                    stored_resource.put()


async def pull_messages(client: Any, subscription: str) -> None:
    """Asynchronously pull and process messages from Pub/Sub.

    Uses asyncio for concurrent message processing with bounded concurrency
    controlled by MAX_CONCURRENT_TASKS semaphore.

    Args:
        client: Pub/Sub discovery client.
        subscription: Full subscription path.
    """
    body = {"returnImmediately": False, "maxMessages": BATCH_SIZE}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)

    while True:
        try:
            # Pub/Sub pull is blocking, run in executor to not block event loop
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: client.projects()
                .subscriptions()
                .pull(subscription=subscription, body=body)
                .execute(num_retries=NUM_RETRIES),
            )
        except Exception:
            await asyncio.sleep(0.5)
            logging.error("pull_messages: pull", exc_info=True)
            continue

        received_messages = resp.get("receivedMessages")

        if received_messages:
            ack_ids = []
            tasks = []

            for received_message in received_messages:
                message = received_message.get("message")
                if message:
                    # Use semaphore to limit concurrent processing
                    async def process_with_semaphore(msg: dict[str, Any]) -> None:
                        async with semaphore:
                            await process(msg)
                            # Allow pending tasks to yield
                            await asyncio.sleep(0)

                    tasks.append(asyncio.create_task(process_with_semaphore(message)))
                    ack_ids.append(received_message.get("ackId"))

            # Wait for all message processing tasks
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            # Acknowledge messages after processing
            ack_body = {"ackIds": ack_ids}

            def make_ack_call(body: dict[str, list[str | None]]) -> Any:
                """Create acknowledge call with captured body."""
                return (
                    client.projects()
                    .subscriptions()
                    .acknowledge(subscription=subscription, body=body)
                    .execute(num_retries=NUM_RETRIES)
                )

            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, make_ack_call, ack_body)
            except Exception:
                await asyncio.sleep(0.5)
                logging.error("pull_messages: acknowledge", exc_info=True)


# =============================================================================
# Main Entry Point
# =============================================================================


async def async_main() -> None:
    """Async main entry point with graceful shutdown handling."""
    # Setup Google Cloud Logging
    try:
        log_client = google.cloud.logging.Client()
        log_client.setup_logging()
    except Exception as e:
        logging.warning(f"Failed to setup Google Cloud Logging: {e}")

    global VALID_TYPES
    client = discovery.build("pubsub", "v1", credentials=CREDENTIALS)
    VALID_TYPES = {p["resource"] for p in POLICIES}

    default_sub = (
        SETTINGS.get("sheriff", {})
        .get("pubsub", {})
        .get("subscription", "projects/pcln-pl-infra-prod/subscriptions/compute-sheriff")
    )

    # Setup graceful shutdown
    shutdown_event = asyncio.Event()

    def signal_handler() -> None:
        logging.info("Shutdown signal received, stopping...")
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    # Run message loop until shutdown
    try:
        pull_task = asyncio.create_task(pull_messages(client, default_sub))
        await shutdown_event.wait()
        pull_task.cancel()
        try:
            await pull_task
        except asyncio.CancelledError:
            logging.info("Message processing stopped")
    finally:
        # Cleanup async clients
        await api.CLIENTS.close()
        logging.info("Sheriff shutdown complete")


def main() -> None:
    """Synchronous entry point - runs the async main."""
    asyncio.run(async_main())


# Object initialization
PROJECT_RESOURCE_MAP: dict[str, Any] = {}
CREDENTIALS, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])

if __name__ == "__main__":
    main()
