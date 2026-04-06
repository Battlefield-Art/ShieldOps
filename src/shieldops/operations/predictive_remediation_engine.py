"""Predictive Remediation Engine — predictive remediation before incidents occur."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PredictiveRemediationEngine = engine(
    "PredictiveRemediationEngine",
    description="Predictive Remediation Engine — predictive remediation before incidents occur.",
    enums={
        "remediation_type": EnumDef(
            "RemediationType",
            {
                "SCALING": "scaling",
                "RESTART": "restart",
                "CONFIG_CHANGE": "config_change",
                "PATCH": "patch",
                "FAILOVER": "failover",
            },
        ),
        "prediction_source": EnumDef(
            "PredictionSource",
            {
                "ANOMALY_DETECTION": "anomaly_detection",
                "TREND_ANALYSIS": "trend_analysis",
                "PATTERN_MATCH": "pattern_match",
                "ML_FORECAST": "ml_forecast",
                "RULE_BASED": "rule_based",
            },
        ),
        "remediation_urgency": EnumDef(
            "RemediationUrgency",
            {
                "IMMEDIATE": "immediate",
                "PROACTIVE": "proactive",
                "SCHEDULED": "scheduled",
                "ADVISORY": "advisory",
                "DEFERRED": "deferred",
            },
        ),
    },
)

# Backward-compatible re-exports
RemediationType = PredictiveRemediationEngine.RemediationType
PredictionSource = PredictiveRemediationEngine.PredictionSource
RemediationUrgency = PredictiveRemediationEngine.RemediationUrgency
PredictiveRecord = PredictiveRemediationEngine.Record
PredictiveAnalysis = PredictiveRemediationEngine.Analysis
PredictiveRemediationReport = PredictiveRemediationEngine.Report
