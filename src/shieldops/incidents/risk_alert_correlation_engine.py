"""Risk Alert Correlation Engine correlate risk alerts, build attack timelines, compute correl..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RiskAlertCorrelationEngine = engine(
    "RiskAlertCorrelationEngine",
    description="Correlate risk alerts, build attack timelines, compute correlation confidence.",
    enums={
        "corr_type": EnumDef(
            "CorrelationType",
            {
                "TEMPORAL": "temporal",
                "ENTITY": "entity",
                "TECHNIQUE": "technique",
                "CAMPAIGN": "campaign",
            },
        ),
        "strength": EnumDef(
            "CorrelationStrength",
            {
                "STRONG": "strong",
                "MODERATE": "moderate",
                "WEAK": "weak",
                "NONE": "none",
            },
        ),
        "relation": EnumDef(
            "AlertRelation",
            {
                "CAUSAL": "causal",
                "CONCURRENT": "concurrent",
                "SEQUENTIAL": "sequential",
                "INDEPENDENT": "independent",
            },
        ),
    },
    record_fields=[
        FieldDef("alert_id_a", str, ""),
        FieldDef("alert_id_b", str, ""),
        FieldDef("entity_id", str, ""),
        FieldDef("confidence", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="correlation_id",
)

# Backward-compatible re-exports
CorrelationType = RiskAlertCorrelationEngine.CorrelationType
CorrelationStrength = RiskAlertCorrelationEngine.CorrelationStrength
AlertRelation = RiskAlertCorrelationEngine.AlertRelation
RiskAlertCorrelationRecord = RiskAlertCorrelationEngine.Record
RiskAlertCorrelationAnalysis = RiskAlertCorrelationEngine.Analysis
RiskAlertCorrelationReport = RiskAlertCorrelationEngine.Report
