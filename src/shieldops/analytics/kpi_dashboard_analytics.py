"""KPIDashboardAnalytics — KPI tracking."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

KPIDashboardAnalytics = engine(
    "KPIDashboardAnalytics",
    description="Track and analyze KPIs.",
    enums={
        "kpi_category": EnumDef(
            "KPICategory",
            {
                "SECURITY": "security",
                "OPERATIONAL": "operational",
                "COMPLIANCE": "compliance",
                "FINANCIAL": "financial",
            },
        ),
        "target_status": EnumDef(
            "TargetStatus",
            {
                "ON_TARGET": "on_target",
                "AT_RISK": "at_risk",
                "MISSED": "missed",
                "EXCEEDED": "exceeded",
            },
        ),
        "board_metric": EnumDef(
            "BoardMetric",
            {
                "MTTR": "mttr",
                "MTTD": "mttd",
                "INCIDENT_RATE": "incident_rate",
                "COMPLIANCE_SCORE": "compliance_score",
                "COST_PER_FINDING": "cost_per_finding",
            },
        ),
    },
    record_fields=[
        FieldDef("target_value", float, 0.0),
        FieldDef("actual_value", float, 0.0),
        FieldDef("entity", str, ""),
    ],
)

# Backward-compatible re-exports
KPICategory = KPIDashboardAnalytics.KPICategory
TargetStatus = KPIDashboardAnalytics.TargetStatus
BoardMetric = KPIDashboardAnalytics.BoardMetric
KPIDashboardRecord = KPIDashboardAnalytics.Record
KPIDashboardAnalysis = KPIDashboardAnalytics.Analysis
KPIDashboardReport = KPIDashboardAnalytics.Report
