"""Adaptive Playbook Engine — manage dynamic playbook adaptation."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AdaptivePlaybookEngine = engine(
    "AdaptivePlaybookEngine",
    description="Manage dynamic playbook adaptation.",
    enums={
        "adaptation_trigger": EnumDef(
            "AdaptationTrigger",
            {
                "FINDING_CHANGE": "finding_change",
                "CONFIDENCE_DROP": "confidence_drop",
                "NEW_IOC": "new_ioc",
                "ANALYST_OVERRIDE": "analyst_override",
            },
        ),
        "adaptation_scope": EnumDef(
            "AdaptationScope",
            {
                "STEP": "step",
                "BRANCH": "branch",
                "FULL_REWRITE": "full_rewrite",
            },
        ),
        "adaptation_outcome": EnumDef(
            "AdaptationOutcome",
            {
                "IMPROVED": "improved",
                "NEUTRAL": "neutral",
                "DEGRADED": "degraded",
            },
        ),
    },
    record_fields=[
        FieldDef("before_score", float, 0.0),
        FieldDef("after_score", float, 0.0),
        FieldDef("playbook_id", str, ""),
    ],
)

# Backward-compatible re-exports
AdaptationTrigger = AdaptivePlaybookEngine.AdaptationTrigger
AdaptationScope = AdaptivePlaybookEngine.AdaptationScope
AdaptationOutcome = AdaptivePlaybookEngine.AdaptationOutcome
AdaptivePlaybookRecord = AdaptivePlaybookEngine.Record
AdaptivePlaybookAnalysis = AdaptivePlaybookEngine.Analysis
AdaptivePlaybookReport = AdaptivePlaybookEngine.Report
