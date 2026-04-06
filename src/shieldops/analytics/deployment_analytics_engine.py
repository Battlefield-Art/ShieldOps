"""DeploymentAnalyticsEngine DORA metrics intelligence, deployment frequency analysis, lead ti..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DeploymentAnalyticsEngine = engine(
    "DeploymentAnalyticsEngine",
    module="operations",  # uses record_item
    description="DORA metrics intelligence with deployment frequency and lead time analysis.",
    enums={
        "dora_metric": EnumDef(
            "DORAMetric",
            {
                "DEPLOYMENT_FREQUENCY": "deployment_frequency",
                "LEAD_TIME": "lead_time",
                "CHANGE_FAILURE_RATE": "change_failure_rate",
                "MTTR": "mttr",
            },
        ),
        "performance_level": EnumDef(
            "PerformanceLevel",
            {
                "ELITE": "elite",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNKNOWN": "unknown",
            },
        ),
        "deployment_class": EnumDef(
            "DeploymentClass",
            {
                "STANDARD": "standard",
                "HOTFIX": "hotfix",
                "ROLLBACK": "rollback",
                "EMERGENCY": "emergency",
                "SCHEDULED": "scheduled",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_value", float, 0.0),
        FieldDef("lead_time_hours", float, 0.0),
        FieldDef("change_failure_rate_pct", float, 0.0),
        FieldDef("mttr_minutes", float, 0.0),
        FieldDef("deploys_per_day", float, 0.0),
        FieldDef("pipeline_duration_minutes", float, 0.0),
    ],
)

# Backward-compatible re-exports
DORAMetric = DeploymentAnalyticsEngine.DORAMetric
PerformanceLevel = DeploymentAnalyticsEngine.PerformanceLevel
DeploymentClass = DeploymentAnalyticsEngine.DeploymentClass
DeploymentAnalyticsRecord = DeploymentAnalyticsEngine.Record
DeploymentAnalyticsAnalysis = DeploymentAnalyticsEngine.Analysis
DeploymentAnalyticsReport = DeploymentAnalyticsEngine.Report
