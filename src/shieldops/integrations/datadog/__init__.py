"""Datadog Observability Integration for ShieldOps.

Provides log ingestion, metric time-series, APM trace export,
and pre-built monitors for monitoring autonomous SRE agents.
"""

from shieldops.integrations.datadog.ingest import (
    DatadogClient,
    DatadogLogEntry,
    DatadogMetricPoint,
    DatadogMetricType,
    DatadogSpan,
)
from shieldops.integrations.datadog.monitors import (
    DatadogMonitor,
    DatadogMonitorManager,
)

__all__ = [
    "DatadogClient",
    "DatadogLogEntry",
    "DatadogMetricPoint",
    "DatadogMetricType",
    "DatadogMonitor",
    "DatadogMonitorManager",
    "DatadogSpan",
]
