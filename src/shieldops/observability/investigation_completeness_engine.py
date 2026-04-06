"""Investigation Completeness Engine — verify investigation completeness and thoroughness, enu..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

InvestigationCompletenessEngine = engine(
    "InvestigationCompletenessEngine",
    description="Verify investigation completeness and thoroughness, enumerate open gaps, re...",
    enums={
        "completeness_level": EnumDef(
            "CompletenessLevel",
            {
                "THOROUGH": "thorough",
                "ADEQUATE": "adequate",
                "INCOMPLETE": "incomplete",
                "SUPERFICIAL": "superficial",
            },
        ),
        "gap_type": EnumDef(
            "GapType",
            {
                "UNEXPLORED_HYPOTHESIS": "unexplored_hypothesis",
                "UNVERIFIED_ASSUMPTION": "unverified_assumption",
                "MISSING_DATA": "missing_data",
                "UNTESTED_ALTERNATIVE": "untested_alternative",
            },
        ),
        "verification_status": EnumDef(
            "VerificationStatus",
            {
                "VERIFIED": "verified",
                "PARTIALLY_VERIFIED": "partially_verified",
                "UNVERIFIED": "unverified",
                "CONTRADICTED": "contradicted",
            },
        ),
    },
    record_fields=[
        FieldDef("open_gap_count", int, 0),
        FieldDef("hypothesis_count", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="completeness_score",
    key_field="investigation_id",
)

# Backward-compatible re-exports
CompletenessLevel = InvestigationCompletenessEngine.CompletenessLevel
GapType = InvestigationCompletenessEngine.GapType
VerificationStatus = InvestigationCompletenessEngine.VerificationStatus
InvestigationCompletenessRecord = InvestigationCompletenessEngine.Record
InvestigationCompletenessAnalysis = InvestigationCompletenessEngine.Analysis
InvestigationCompletenessReport = InvestigationCompletenessEngine.Report
