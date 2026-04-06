"""Fleet Health Monitor — check agent health and resources."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

FleetHealthMonitor = engine(
    "FleetHealthMonitor",
    module="operations",  # uses record_item
    description="Monitor agent fleet health and resources.",
    enums={
        "health": EnumDef(
            "HealthCheck",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "UNHEALTHY": "unhealthy",
                "UNKNOWN": "unknown",
            },
        ),
        "resource_usage": EnumDef(
            "ResourceUsage",
            {
                "LOW": "low",
                "MODERATE": "moderate",
                "HIGH": "high",
                "CRITICAL": "critical",
            },
        ),
        "alert_level": EnumDef(
            "AlertThreshold",
            {
                "INFO": "info",
                "WARNING": "warning",
                "ERROR": "error",
                "CRITICAL": "critical",
            },
        ),
    },
    key_field="agent_name",
)

# Backward-compatible re-exports
HealthCheck = FleetHealthMonitor.HealthCheck
ResourceUsage = FleetHealthMonitor.ResourceUsage
AlertThreshold = FleetHealthMonitor.AlertThreshold
HealthRecord = FleetHealthMonitor.Record
HealthAnalysis = FleetHealthMonitor.Analysis
HealthReport = FleetHealthMonitor.Report
