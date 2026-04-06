"""Improvement Attribution Engine — attribute improvements to changes, detect confounded exper..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ImprovementAttributionEngine = engine(
    "ImprovementAttributionEngine",
    description="Attribute improvements to changes, detect confounded experiments, and build...",
    enums={
        "change_type": EnumDef(
            "ChangeType",
            {
                "PARAMETER_CHANGE": "parameter_change",
                "DATA_CHANGE": "data_change",
                "ARCHITECTURE_CHANGE": "architecture_change",
                "PROMPT_CHANGE": "prompt_change",
            },
        ),
        "attribution_confidence": EnumDef(
            "AttributionConfidence",
            {
                "CAUSAL": "causal",
                "CORRELATIONAL": "correlational",
                "SUGGESTIVE": "suggestive",
                "UNCERTAIN": "uncertain",
            },
        ),
        "magnitude": EnumDef(
            "ImprovementMagnitude",
            {
                "BREAKTHROUGH": "breakthrough",
                "SIGNIFICANT": "significant",
                "MARGINAL": "marginal",
                "NEGLIGIBLE": "negligible",
            },
        ),
    },
    record_fields=[
        FieldDef("change_id", str, ""),
        FieldDef("improvement_delta", float, 0.0),
        FieldDef("confounded", bool, False),
        FieldDef("simultaneous_changes", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="experiment_id",
)

# Backward-compatible re-exports
ChangeType = ImprovementAttributionEngine.ChangeType
AttributionConfidence = ImprovementAttributionEngine.AttributionConfidence
ImprovementMagnitude = ImprovementAttributionEngine.ImprovementMagnitude
ImprovementAttributionRecord = ImprovementAttributionEngine.Record
ImprovementAttributionAnalysis = ImprovementAttributionEngine.Analysis
ImprovementAttributionReport = ImprovementAttributionEngine.Report
