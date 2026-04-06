"""Cost Anomaly Root Cause Engine correlate anomalies with events, decompose contributors, ass..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CostAnomalyRootCauseEngine = engine(
    "CostAnomalyRootCauseEngine",
    description="Correlate anomalies with events, decompose contributors, assess recurrence...",
    enums={
        "anomaly_type": EnumDef(
            "AnomalyType",
            {
                "SPIKE": "spike",
                "DRIFT": "drift",
                "STEP_CHANGE": "step_change",
                "SEASONAL": "seasonal",
            },
        ),
        "event_correlation": EnumDef(
            "EventCorrelation",
            {
                "DEPLOYMENT": "deployment",
                "SCALING": "scaling",
                "CONFIG_CHANGE": "config_change",
                "TRAFFIC": "traffic",
            },
        ),
        "recurrence_risk": EnumDef(
            "RecurrenceRisk",
            {
                "LIKELY": "likely",
                "POSSIBLE": "possible",
                "UNLIKELY": "unlikely",
                "ONE_TIME": "one_time",
            },
        ),
    },
    record_fields=[
        FieldDef("anomaly_amount", float, 0.0),
        FieldDef("baseline_amount", float, 0.0),
        FieldDef("service_name", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="anomaly_id",
)

# Backward-compatible re-exports
AnomalyType = CostAnomalyRootCauseEngine.AnomalyType
EventCorrelation = CostAnomalyRootCauseEngine.EventCorrelation
RecurrenceRisk = CostAnomalyRootCauseEngine.RecurrenceRisk
CostAnomalyRecord = CostAnomalyRootCauseEngine.Record
CostAnomalyAnalysis = CostAnomalyRootCauseEngine.Analysis
CostAnomalyReport = CostAnomalyRootCauseEngine.Report
