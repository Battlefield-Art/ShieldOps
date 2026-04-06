"""Policy as Code Effectiveness Scorer score policy coverage, detect blind spots, rank policie..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PolicyAsCodeEffectivenessScorer = engine(
    "PolicyAsCodeEffectivenessScorer",
    description="Score policy coverage, detect blind spots, rank policies by enforcement eff...",
    enums={
        "policy_language": EnumDef(
            "PolicyLanguage",
            {
                "REGO": "rego",
                "SENTINEL": "sentinel",
                "CUE": "cue",
                "CUSTOM": "custom",
            },
        ),
        "coverage_level": EnumDef(
            "CoverageLevel",
            {
                "COMPREHENSIVE": "comprehensive",
                "ADEQUATE": "adequate",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
            },
        ),
        "enforcement_mode": EnumDef(
            "EnforcementMode",
            {
                "BLOCKING": "blocking",
                "WARNING": "warning",
                "AUDIT": "audit",
                "DISABLED": "disabled",
            },
        ),
    },
    record_fields=[
        FieldDef("policy_name", str, ""),
        FieldDef("violations_caught", int, 0),
        FieldDef("violations_missed", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="effectiveness_score",
    key_field="policy_id",
)

# Backward-compatible re-exports
PolicyLanguage = PolicyAsCodeEffectivenessScorer.PolicyLanguage
CoverageLevel = PolicyAsCodeEffectivenessScorer.CoverageLevel
EnforcementMode = PolicyAsCodeEffectivenessScorer.EnforcementMode
PolicyEffectivenessRecord = PolicyAsCodeEffectivenessScorer.Record
PolicyEffectivenessAnalysis = PolicyAsCodeEffectivenessScorer.Analysis
PolicyEffectivenessReport = PolicyAsCodeEffectivenessScorer.Report
