"""Compliance Evidence Correlation Engine compute evidence reuse ratio, detect redundant colle..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ComplianceEvidenceCorrelationEngine = engine(
    "ComplianceEvidenceCorrelationEngine",
    description="Compute evidence reuse ratio, detect redundant collections, rank evidence b...",
    enums={
        "correlation_type": EnumDef(
            "CorrelationType",
            {
                "EXACT_MATCH": "exact_match",
                "PARTIAL_OVERLAP": "partial_overlap",
                "DERIVED": "derived",
                "INDEPENDENT": "independent",
            },
        ),
        "evidence_scope": EnumDef(
            "EvidenceScope",
            {
                "SINGLE_CONTROL": "single_control",
                "MULTI_CONTROL": "multi_control",
                "CROSS_FRAMEWORK": "cross_framework",
                "UNIVERSAL": "universal",
            },
        ),
        "correlation_strength": EnumDef(
            "CorrelationStrength",
            {
                "STRONG": "strong",
                "MODERATE": "moderate",
                "WEAK": "weak",
                "NONE": "none",
            },
        ),
    },
    record_fields=[
        FieldDef("reuse_count", int, 0),
        FieldDef("control_count", int, 1),
        FieldDef("collection_cost", float, 0.0),
        FieldDef("control_id", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="evidence_id",
)

# Backward-compatible re-exports
CorrelationType = ComplianceEvidenceCorrelationEngine.CorrelationType
EvidenceScope = ComplianceEvidenceCorrelationEngine.EvidenceScope
CorrelationStrength = ComplianceEvidenceCorrelationEngine.CorrelationStrength
EvidenceCorrelationRecord = ComplianceEvidenceCorrelationEngine.Record
EvidenceCorrelationAnalysis = ComplianceEvidenceCorrelationEngine.Analysis
EvidenceCorrelationReport = ComplianceEvidenceCorrelationEngine.Report
