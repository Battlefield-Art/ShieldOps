"""EdgeTelemetryProcessor — edge telemetry processing engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EdgeTelemetryProcessor = engine(
    "EdgeTelemetryProcessor",
    description="Edge Telemetry Processor. Processes and optimizes telemetry data from edge...",
    enums={
        "edge_node_type": EnumDef(
            "EdgeNodeType",
            {
                "GATEWAY": "gateway",
                "SENSOR": "sensor",
                "PROXY": "proxy",
                "COLLECTOR": "collector",
            },
        ),
        "protocol": EnumDef(
            "TelemetryProtocol",
            {
                "OTLP": "otlp",
                "PROMETHEUS": "prometheus",
                "STATSD": "statsd",
                "SYSLOG": "syslog",
            },
        ),
        "processing_mode": EnumDef(
            "ProcessingMode",
            {
                "STREAMING": "streaming",
                "BATCH": "batch",
                "HYBRID": "hybrid",
            },
        ),
    },
    record_fields=[
        FieldDef("latency_ms", float, 0.0),
        FieldDef("throughput_eps", float, 0.0),
    ],
)

# Backward-compatible re-exports
EdgeNodeType = EdgeTelemetryProcessor.EdgeNodeType
TelemetryProtocol = EdgeTelemetryProcessor.TelemetryProtocol
ProcessingMode = EdgeTelemetryProcessor.ProcessingMode
EdgeTelemetryRecord = EdgeTelemetryProcessor.Record
EdgeTelemetryAnalysis = EdgeTelemetryProcessor.Analysis
EdgeTelemetryReport = EdgeTelemetryProcessor.Report
