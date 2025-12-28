"""Sheriff - GCP Resource Life-Cycle Management.

A policy-driven automation framework for monitoring GCP Pub/Sub
event streams and enforcing security, compliance, and operational standards.
"""

from sheriff.main import log_event, main, record_metric, slack

__version__ = "0.1.0"
__all__ = ["main", "log_event", "record_metric", "slack", "__version__"]
