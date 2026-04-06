"""Risk Trend Intelligence compute risk trajectory, detect risk anomalies, forecast risk level..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RiskTrendIntelligence = engine(
    "RiskTrendIntelligence",
    description="Compute risk trajectory, detect anomalies, forecast risk levels.",
    enums={
        "window": EnumDef(
            "TrendWindow",
            {
                "HOURLY": "hourly",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
            },
        ),
        "direction": EnumDef(
            "TrendDirection",
            {
                "ESCALATING": "escalating",
                "STABLE": "stable",
                "DECLINING": "declining",
                "VOLATILE": "volatile",
            },
        ),
        "domain": EnumDef(
            "RiskDomain",
            {
                "IDENTITY": "identity",
                "NETWORK": "network",
                "ENDPOINT": "endpoint",
                "CLOUD": "cloud",
            },
        ),
    },
    record_fields=[
        FieldDef("previous_score", float, 0.0),
        FieldDef("entity_id", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="risk_score",
    key_field="trend_id",
)

# Backward-compatible re-exports
TrendWindow = RiskTrendIntelligence.TrendWindow
TrendDirection = RiskTrendIntelligence.TrendDirection
RiskDomain = RiskTrendIntelligence.RiskDomain
RiskTrendRecord = RiskTrendIntelligence.Record
RiskTrendAnalysis = RiskTrendIntelligence.Analysis
RiskTrendReport = RiskTrendIntelligence.Report
