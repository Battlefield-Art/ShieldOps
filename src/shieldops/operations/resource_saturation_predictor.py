"""Resource Saturation Predictor compute saturation timeline, detect approaching saturation, r..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ResourceSaturationPredictor = engine(
    "ResourceSaturationPredictor",
    module="operations",  # uses record_item
    description="Compute saturation timeline, detect approaching saturation, rank resources...",
    enums={
        "saturation_level": EnumDef(
            "SaturationLevel",
            {
                "SAFE": "safe",
                "WARNING": "warning",
                "DANGER": "danger",
                "CRITICAL": "critical",
            },
        ),
        "resource_category": EnumDef(
            "ResourceCategory",
            {
                "COMPUTE": "compute",
                "MEMORY": "memory",
                "STORAGE": "storage",
                "NETWORK": "network",
            },
        ),
        "prediction_confidence": EnumDef(
            "PredictionConfidence",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNCERTAIN": "uncertain",
            },
        ),
    },
    record_fields=[
        FieldDef("current_usage_pct", float, 0.0),
        FieldDef("predicted_usage_pct", float, 0.0),
        FieldDef("hours_to_saturation", float, 0.0),
        FieldDef("host", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="resource_id",
)

# Backward-compatible re-exports
SaturationLevel = ResourceSaturationPredictor.SaturationLevel
ResourceCategory = ResourceSaturationPredictor.ResourceCategory
PredictionConfidence = ResourceSaturationPredictor.PredictionConfidence
ResourceSaturationRecord = ResourceSaturationPredictor.Record
ResourceSaturationAnalysis = ResourceSaturationPredictor.Analysis
ResourceSaturationReport = ResourceSaturationPredictor.Report
