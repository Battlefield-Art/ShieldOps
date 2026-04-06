"""Synthetic Monitoring Intelligence — synthetic monitoring intelligence and endpoint health."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SyntheticMonitoringIntelligence = engine(
    "SyntheticMonitoringIntelligence",
    description="Synthetic Monitoring Intelligence — synthetic monitoring intelligence and e...",
    enums={
        "synthetic_check_type": EnumDef(
            "SyntheticCheckType",
            {
                "HTTP": "http",
                "API": "api",
                "BROWSER": "browser",
                "DNS": "dns",
                "TCP": "tcp",
            },
        ),
        "synthetic_source": EnumDef(
            "SyntheticSource",
            {
                "DATADOG": "datadog",
                "GRAFANA": "grafana",
                "PINGDOM": "pingdom",
                "UPTIME_ROBOT": "uptime_robot",
                "CUSTOM": "custom",
            },
        ),
        "check_reliability": EnumDef(
            "CheckReliability",
            {
                "RELIABLE": "reliable",
                "FLAKY": "flaky",
                "DEGRADED": "degraded",
                "FAILING": "failing",
                "DISABLED": "disabled",
            },
        ),
    },
)

# Backward-compatible re-exports
SyntheticCheckType = SyntheticMonitoringIntelligence.SyntheticCheckType
SyntheticSource = SyntheticMonitoringIntelligence.SyntheticSource
CheckReliability = SyntheticMonitoringIntelligence.CheckReliability
SyntheticRecord = SyntheticMonitoringIntelligence.Record
SyntheticAnalysis = SyntheticMonitoringIntelligence.Analysis
SyntheticMonitoringReport = SyntheticMonitoringIntelligence.Report
