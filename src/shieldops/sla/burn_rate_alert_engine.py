"""Burn Rate Alert Engine — track SLO burn rate alerts and response."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

BurnRateAlertEngine = engine(
    "BurnRateAlertEngine",
    description="Track SLO burn rate alerts and response effectiveness.",
    enums={
        "alert_window": EnumDef(
            "AlertWindow",
            {
                "ONE_HOUR": "one_hour",
                "SIX_HOUR": "six_hour",
                "ONE_DAY": "one_day",
                "THREE_DAY": "three_day",
                "THIRTY_DAY": "thirty_day",
            },
        ),
        "alert_severity": EnumDef(
            "AlertSeverity",
            {
                "PAGE": "page",
                "TICKET": "ticket",
                "WARNING": "warning",
                "INFO": "info",
                "RESOLVED": "resolved",
            },
        ),
        "response_outcome": EnumDef(
            "ResponseOutcome",
            {
                "MITIGATED": "mitigated",
                "ESCALATED": "escalated",
                "AUTO_RESOLVED": "auto_resolved",
                "FALSE_ALARM": "false_alarm",
                "ONGOING": "ongoing",
            },
        ),
    },
    record_fields=[
        FieldDef("slo_name", str, ""),
        FieldDef("burn_rate_multiplier", float, 1.0),
        FieldDef("error_budget_consumed_pct", float, 0.0),
        FieldDef("response_time_seconds", float, 0.0),
        FieldDef("mitigation_time_seconds", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="service_id",
)

# Backward-compatible re-exports
AlertWindow = BurnRateAlertEngine.AlertWindow
AlertSeverity = BurnRateAlertEngine.AlertSeverity
ResponseOutcome = BurnRateAlertEngine.ResponseOutcome
BurnRateAlertRecord = BurnRateAlertEngine.Record
BurnRateAlertAnalysis = BurnRateAlertEngine.Analysis
BurnRateAlertReport = BurnRateAlertEngine.Report
