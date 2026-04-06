"""Oncall Burden Analyzer calculate burden index, detect burden imbalance, forecast burnout risk."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OncallBurdenAnalyzer = engine(
    "OncallBurdenAnalyzer",
    description="Calculate burden index, detect burden imbalance, forecast burnout risk.",
    enums={
        "burden_level": EnumDef(
            "BurdenLevel",
            {
                "EXTREME": "extreme",
                "HIGH": "high",
                "MODERATE": "moderate",
                "SUSTAINABLE": "sustainable",
            },
        ),
        "shift_period": EnumDef(
            "ShiftPeriod",
            {
                "BUSINESS_HOURS": "business_hours",
                "EVENING": "evening",
                "OVERNIGHT": "overnight",
                "WEEKEND": "weekend",
            },
        ),
        "burnout_risk": EnumDef(
            "BurnoutRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("pages_received", int, 0),
        FieldDef("hours_on_call", float, 0.0),
        FieldDef("incidents_handled", int, 0),
    ],
    key_field="responder_id",
)

# Backward-compatible re-exports
BurdenLevel = OncallBurdenAnalyzer.BurdenLevel
ShiftPeriod = OncallBurdenAnalyzer.ShiftPeriod
BurnoutRisk = OncallBurdenAnalyzer.BurnoutRisk
OncallBurdenRecord = OncallBurdenAnalyzer.Record
OncallBurdenAnalysis = OncallBurdenAnalyzer.Analysis
OncallBurdenReport = OncallBurdenAnalyzer.Report
