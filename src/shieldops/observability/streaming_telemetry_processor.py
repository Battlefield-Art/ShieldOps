"""Streaming Telemetry Processor — streaming telemetry processing and real-time signal ingestion."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

StreamingTelemetryProcessor = engine(
    "StreamingTelemetryProcessor",
    description="Streaming Telemetry Processor streaming telemetry processing and real-time...",
    enums={
        "processor_type": EnumDef(
            "ProcessorType",
            {
                "METRIC": "metric",
                "LOG": "log",
                "TRACE": "trace",
                "EVENT": "event",
                "PROFILE": "profile",
            },
        ),
        "processor_source": EnumDef(
            "ProcessorSource",
            {
                "OTEL_COLLECTOR": "otel_collector",
                "PROMETHEUS": "prometheus",
                "DATADOG": "datadog",
                "CLOUDWATCH": "cloudwatch",
                "CUSTOM": "custom",
            },
        ),
        "processor_status": EnumDef(
            "ProcessorStatus",
            {
                "ACTIVE": "active",
                "DEGRADED": "degraded",
                "BUFFERING": "buffering",
                "THROTTLED": "throttled",
                "OFFLINE": "offline",
            },
        ),
    },
)

# Backward-compatible re-exports
ProcessorType = StreamingTelemetryProcessor.ProcessorType
ProcessorSource = StreamingTelemetryProcessor.ProcessorSource
ProcessorStatus = StreamingTelemetryProcessor.ProcessorStatus
ProcessorRecord = StreamingTelemetryProcessor.Record
ProcessorAnalysis = StreamingTelemetryProcessor.Analysis
StreamingTelemetryReport = StreamingTelemetryProcessor.Report
