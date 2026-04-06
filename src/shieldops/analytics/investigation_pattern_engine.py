"""InvestigationPatternEngine — Learn recurring investigation patterns for faster resolution."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

InvestigationPatternEngine = engine(
    "InvestigationPatternEngine",
    description="Learn recurring investigation patterns for faster future resolution.",
    enums={
        "pattern_type": EnumDef(
            "PatternType",
            {
                "SYMPTOM_CLUSTER": "symptom_cluster",
                "ROOT_CAUSE_SIGNATURE": "root_cause_signature",
                "RESOLUTION_TEMPLATE": "resolution_template",
            },
        ),
        "pattern_confidence": EnumDef(
            "PatternConfidence",
            {
                "VALIDATED": "validated",
                "EMERGING": "emerging",
                "SPECULATIVE": "speculative",
            },
        ),
        "match_quality": EnumDef(
            "MatchQuality",
            {
                "EXACT": "exact",
                "SIMILAR": "similar",
                "PARTIAL": "partial",
            },
        ),
    },
    record_fields=[
        FieldDef("match_count", int, 0),
        FieldDef("pattern_hash", str, ""),
    ],
)

# Backward-compatible re-exports
PatternType = InvestigationPatternEngine.PatternType
PatternConfidence = InvestigationPatternEngine.PatternConfidence
MatchQuality = InvestigationPatternEngine.MatchQuality
InvestigationPatternRecord = InvestigationPatternEngine.Record
InvestigationPatternAnalysis = InvestigationPatternEngine.Analysis
InvestigationPatternReport = InvestigationPatternEngine.Report
