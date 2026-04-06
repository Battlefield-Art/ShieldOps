"""Incident Response Metrics Tracker — incident response metrics tracking and SLA monitoring."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IncidentResponseMetricsTracker = engine(
    "IncidentResponseMetricsTracker",
    description="Incident Response Metrics Tracker — incident response metrics tracking and...",
    enums={
        "response_metric": EnumDef(
            "ResponseMetric",
            {
                "MTTD": "mttd",
                "MTTC": "mttc",
                "MTTR": "mttr",
                "MTTE": "mtte",
                "MEAN_DWELL_TIME": "mean_dwell_time",
            },
        ),
        "metric_source": EnumDef(
            "MetricSource",
            {
                "INCIDENT_LOG": "incident_log",
                "SOAR_PLATFORM": "soar_platform",
                "MANUAL_ENTRY": "manual_entry",
                "AUTOMATED": "automated",
                "DERIVED": "derived",
            },
        ),
        "metric_trend": EnumDef(
            "MetricTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "VOLATILE": "volatile",
                "INSUFFICIENT_DATA": "insufficient_data",
            },
        ),
    },
)

# Backward-compatible re-exports
ResponseMetric = IncidentResponseMetricsTracker.ResponseMetric
MetricSource = IncidentResponseMetricsTracker.MetricSource
MetricTrend = IncidentResponseMetricsTracker.MetricTrend
ResponseMetricRecord = IncidentResponseMetricsTracker.Record
ResponseMetricAnalysis = IncidentResponseMetricsTracker.Analysis
IncidentResponseMetricsReport = IncidentResponseMetricsTracker.Report
