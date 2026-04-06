"""TelemetryExporterManager — telemetry exporter management."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

TelemetryExporterManager = engine(
    "TelemetryExporterManager",
    description="Telemetry exporter management engine.",
    enums={
        "exporter_type": EnumDef(
            "ExporterType",
            {
                "OTLP_GRPC": "otlp_grpc",
                "OTLP_HTTP": "otlp_http",
                "SPLUNK_HEC": "splunk_hec",
                "PROMETHEUS": "prometheus",
            },
        ),
        "exporter_status": EnumDef(
            "ExporterStatus",
            {
                "ACTIVE": "active",
                "DEGRADED": "degraded",
                "FAILED": "failed",
                "DISABLED": "disabled",
            },
        ),
        "export_protocol": EnumDef(
            "ExportProtocol",
            {
                "GRPC": "grpc",
                "HTTP": "http",
                "TCP": "tcp",
                "UDP": "udp",
            },
        ),
    },
)

# Backward-compatible re-exports
ExporterType = TelemetryExporterManager.ExporterType
ExporterStatus = TelemetryExporterManager.ExporterStatus
ExportProtocol = TelemetryExporterManager.ExportProtocol
TelemetryExporterManagerRecord = TelemetryExporterManager.Record
TelemetryExporterManagerAnalysis = TelemetryExporterManager.Analysis
TelemetryExporterManagerReport = TelemetryExporterManager.Report
