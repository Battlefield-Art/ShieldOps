"""Infrastructure Telemetry Scorer — infrastructure telemetry coverage scoring and gap detection."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

InfrastructureTelemetryScorer = engine(
    "InfrastructureTelemetryScorer",
    description="Infrastructure Telemetry Scorer infrastructure telemetry coverage scoring a...",
    enums={
        "infra_layer": EnumDef(
            "InfraLayer",
            {
                "COMPUTE": "compute",
                "NETWORK": "network",
                "STORAGE": "storage",
                "DATABASE": "database",
                "CONTAINER": "container",
            },
        ),
        "telemetry_source": EnumDef(
            "TelemetrySource",
            {
                "AGENT": "agent",
                "AGENTLESS": "agentless",
                "CLOUD_API": "cloud_api",
                "SNMP": "snmp",
                "CUSTOM": "custom",
            },
        ),
        "coverage_level": EnumDef(
            "CoverageLevel",
            {
                "COMPLETE": "complete",
                "GOOD": "good",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
                "NONE": "none",
            },
        ),
    },
)

# Backward-compatible re-exports
InfraLayer = InfrastructureTelemetryScorer.InfraLayer
TelemetrySource = InfrastructureTelemetryScorer.TelemetrySource
CoverageLevel = InfrastructureTelemetryScorer.CoverageLevel
InfraTelemetryRecord = InfrastructureTelemetryScorer.Record
InfraTelemetryAnalysis = InfrastructureTelemetryScorer.Analysis
InfrastructureTelemetryReport = InfrastructureTelemetryScorer.Report
