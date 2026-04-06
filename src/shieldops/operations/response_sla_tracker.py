"""Response SLA Tracker — track incident response SLA compliance and metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ResponseSLATracker = engine(
    "ResponseSLATracker",
    description="Track incident response SLA compliance — detect, contain, eradicate, recove...",
    enums={
        "sla_metric": EnumDef(
            "SLAMetric",
            {
                "TIME_TO_DETECT": "time_to_detect",
                "TIME_TO_CONTAIN": "time_to_contain",
                "TIME_TO_ERADICATE": "time_to_eradicate",
                "TIME_TO_RECOVER": "time_to_recover",
                "TIME_TO_CLOSE": "time_to_close",
            },
        ),
        "sla_status": EnumDef(
            "SLAStatus",
            {
                "WITHIN_TARGET": "within_target",
                "AT_RISK": "at_risk",
                "BREACHED": "breached",
                "EXCEEDED": "exceeded",
                "NOT_APPLICABLE": "not_applicable",
            },
        ),
        "sla_severity": EnumDef(
            "SLASeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFO": "info",
            },
        ),
    },
)

# Backward-compatible re-exports
SLAMetric = ResponseSLATracker.SLAMetric
SLAStatus = ResponseSLATracker.SLAStatus
SLASeverity = ResponseSLATracker.SLASeverity
SLARecord = ResponseSLATracker.Record
SLAAnalysis = ResponseSLATracker.Analysis
SLAReport = ResponseSLATracker.Report
