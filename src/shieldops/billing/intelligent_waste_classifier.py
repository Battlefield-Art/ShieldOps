"""Intelligent Waste Classifier classify waste categories, estimate recovery value, prioritize..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IntelligentWasteClassifier = engine(
    "IntelligentWasteClassifier",
    description="Classify waste categories, estimate recovery, prioritize remediation.",
    enums={
        "waste_category": EnumDef(
            "WasteCategory",
            {
                "ORPHANED": "orphaned",
                "OVERSIZED": "oversized",
                "IDLE": "idle",
                "ZOMBIE": "zombie",
            },
        ),
        "remediation_complexity": EnumDef(
            "RemediationComplexity",
            {
                "TRIVIAL": "trivial",
                "MODERATE": "moderate",
                "COMPLEX": "complex",
                "RISKY": "risky",
            },
        ),
        "confidence_level": EnumDef(
            "ConfidenceLevel",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNCERTAIN": "uncertain",
            },
        ),
    },
    record_fields=[
        FieldDef("monthly_waste", float, 0.0),
        FieldDef("resource_type", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="resource_id",
)

# Backward-compatible re-exports
WasteCategory = IntelligentWasteClassifier.WasteCategory
RemediationComplexity = IntelligentWasteClassifier.RemediationComplexity
ConfidenceLevel = IntelligentWasteClassifier.ConfidenceLevel
WasteRecord = IntelligentWasteClassifier.Record
WasteAnalysis = IntelligentWasteClassifier.Analysis
WasteReport = IntelligentWasteClassifier.Report
