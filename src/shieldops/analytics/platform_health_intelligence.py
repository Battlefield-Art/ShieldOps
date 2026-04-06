"""PlatformHealthIntelligence — platform health intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PlatformHealthIntelligence = engine(
    "PlatformHealthIntelligence",
    module="operations",  # uses record_item
    description="Platform Health Intelligence.",
    enums={
        "health_dimension": EnumDef(
            "HealthDimension",
            {
                "INFRASTRUCTURE": "infrastructure",
                "APPLICATION": "application",
                "DATA": "data",
                "SECURITY": "security",
                "OPERATIONS": "operations",
            },
        ),
        "health_status": EnumDef(
            "HealthStatus",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "AT_RISK": "at_risk",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
            },
        ),
        "health_trend": EnumDef(
            "HealthTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DECLINING": "declining",
                "VOLATILE": "volatile",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
HealthDimension = PlatformHealthIntelligence.HealthDimension
HealthStatus = PlatformHealthIntelligence.HealthStatus
HealthTrend = PlatformHealthIntelligence.HealthTrend
PlatformHealthIntelligenceRecord = PlatformHealthIntelligence.Record
PlatformHealthIntelligenceAnalysis = PlatformHealthIntelligence.Analysis
PlatformHealthIntelligenceReport = PlatformHealthIntelligence.Report
