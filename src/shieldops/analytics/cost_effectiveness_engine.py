"""CostEffectivenessEngine — Measure agent cost-effectiveness."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CostEffectivenessEngine = engine(
    "CostEffectivenessEngine",
    description="Measure agent cost-effectiveness (cost per investigation, ROI).",
    enums={
        "cost_category": EnumDef(
            "CostCategory",
            {
                "LLM_TOKENS": "llm_tokens",
                "COMPUTE": "compute",
                "API_CALLS": "api_calls",
                "HUMAN_TIME": "human_time",
            },
        ),
        "roi_indicator": EnumDef(
            "ROIIndicator",
            {
                "POSITIVE": "positive",
                "NEUTRAL": "neutral",
                "NEGATIVE": "negative",
            },
        ),
        "efficiency_quartile": EnumDef(
            "EfficiencyQuartile",
            {
                "TOP": "top",
                "UPPER": "upper",
                "LOWER": "lower",
                "BOTTOM": "bottom",
            },
        ),
    },
    record_fields=[
        FieldDef("cost_usd", float, 0.0),
        FieldDef("time_saved_min", float, 0.0),
    ],
)

# Backward-compatible re-exports
CostCategory = CostEffectivenessEngine.CostCategory
ROIIndicator = CostEffectivenessEngine.ROIIndicator
EfficiencyQuartile = CostEffectivenessEngine.EfficiencyQuartile
CostEffectivenessRecord = CostEffectivenessEngine.Record
CostEffectivenessAnalysis = CostEffectivenessEngine.Analysis
CostEffectivenessReport = CostEffectivenessEngine.Report
