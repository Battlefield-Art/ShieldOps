"""Splunk Observability Cloud Integration for ShieldOps.

Provides metrics ingestion, trace export, custom events, SignalFlow analytics,
and pre-built detectors for monitoring autonomous SRE agents.
"""

from shieldops.integrations.splunk.detectors import (
    DetectorDefinition,
    DetectorSeverity,
    SplunkDetectorManager,
)
from shieldops.integrations.splunk.ingest import (
    MetricType,
    SplunkDataPoint,
    SplunkEvent,
    SplunkIngestClient,
    SplunkSpan,
)
from shieldops.integrations.splunk.signalflow import (
    SignalFlowClient,
    SignalFlowProgram,
    SignalFlowResult,
)

__all__ = [
    "DetectorDefinition",
    "DetectorSeverity",
    "MetricType",
    "SignalFlowClient",
    "SignalFlowProgram",
    "SignalFlowResult",
    "SplunkDataPoint",
    "SplunkDetectorManager",
    "SplunkEvent",
    "SplunkIngestClient",
    "SplunkSpan",
]
