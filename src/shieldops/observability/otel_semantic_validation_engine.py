"""OtelSemanticValidationEngine — Validate OTel semantic conventions compliance."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OtelSemanticValidationEngine = engine(
    "OtelSemanticValidationEngine",
    description="Validate OTel semantic conventions compliance across services.",
    enums={
        "semantic_scope": EnumDef(
            "SemanticScope",
            {
                "RESOURCE": "resource",
                "SPAN": "span",
                "METRIC": "metric",
                "LOG": "log",
            },
        ),
        "compliance_level": EnumDef(
            "ComplianceLevel",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "NONE": "none",
            },
        ),
        "fix_complexity": EnumDef(
            "FixComplexity",
            {
                "TRIVIAL": "trivial",
                "MODERATE": "moderate",
                "COMPLEX": "complex",
            },
        ),
    },
    record_fields=[
        FieldDef("violation_count", int, 0),
        FieldDef("attribute_name", str, ""),
    ],
)

# Backward-compatible re-exports
SemanticScope = OtelSemanticValidationEngine.SemanticScope
ComplianceLevel = OtelSemanticValidationEngine.ComplianceLevel
FixComplexity = OtelSemanticValidationEngine.FixComplexity
OtelSemanticValidationRecord = OtelSemanticValidationEngine.Record
OtelSemanticValidationAnalysis = OtelSemanticValidationEngine.Analysis
OtelSemanticValidationReport = OtelSemanticValidationEngine.Report
