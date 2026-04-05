"""Alert Fatigue Mitigator — reduce alert fatigue through intelligent mitigation strategies."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AlertFatigueMitigator = engine(
    "AlertFatigueMitigator",
    description="Reduce alert fatigue through intelligent mitigation strategies and scoring.",
    enums={
        "fatigue_source": EnumDef(
            "FatigueSource",
            {
                "VOLUME_OVERLOAD": "volume_overload",
                "REPETITIVE_ALERTS": "repetitive_alerts",
                "LOW_FIDELITY": "low_fidelity",
                "POOR_CONTEXT": "poor_context",
                "IRRELEVANT": "irrelevant",
            },
        ),
        "mitigation_strategy": EnumDef(
            "MitigationStrategy",
            {
                "AGGREGATION": "aggregation",
                "DEDUPLICATION": "deduplication",
                "PRIORITIZATION": "prioritization",
                "SUPPRESSION": "suppression",
                "ENRICHMENT": "enrichment",
            },
        ),
        "fatigue_level": EnumDef(
            "FatigueLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "HEALTHY": "healthy",
            },
        ),
    },
    score_field="fatigue_score",
    key_field="source_name",
)

# Backward-compatible re-exports
FatigueSource = AlertFatigueMitigator.FatigueSource
MitigationStrategy = AlertFatigueMitigator.MitigationStrategy
FatigueLevel = AlertFatigueMitigator.FatigueLevel
FatigueRecord = AlertFatigueMitigator.Record
FatigueAnalysis = AlertFatigueMitigator.Analysis
FatigueReport = AlertFatigueMitigator.Report
