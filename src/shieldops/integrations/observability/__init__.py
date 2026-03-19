"""Observability integration layer for ShieldOps.

Provides unified log/metric/trace ingestion and querying
compatible with OpenObserve, Elasticsearch, and local storage backends.
"""

from shieldops.integrations.observability.ingest import (
    IngestResult,
    ObservabilityBackend,
    ObservabilityIngestClient,
    SignalType,
    TelemetryRecord,
)

__all__ = [
    "IngestResult",
    "ObservabilityBackend",
    "ObservabilityIngestClient",
    "SignalType",
    "TelemetryRecord",
]
