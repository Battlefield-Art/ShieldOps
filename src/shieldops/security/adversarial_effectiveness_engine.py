"""Adversarial Effectiveness Engine — track red/blue validation effectiveness."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AdversarialEffectivenessEngine = engine(
    "AdversarialEffectivenessEngine",
    description="Track red/blue validation effectiveness across defense categories.",
    enums={
        "validation_outcome": EnumDef(
            "ValidationOutcome",
            {
                "BLOCKED": "blocked",
                "DETECTED": "detected",
                "BYPASSED": "bypassed",
                "INCONCLUSIVE": "inconclusive",
                "REGRESSION": "regression",
            },
        ),
        "defense_category": EnumDef(
            "DefenseCategory",
            {
                "FIREWALL": "firewall",
                "POLICY": "policy",
                "CREDENTIAL": "credential",
                "CONFIG": "config",
                "DETECTION": "detection",
            },
        ),
        "trend_direction": EnumDef(
            "TrendDirection",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "VOLATILE": "volatile",
                "NEW": "new",
            },
        ),
    },
    record_fields=[
        FieldDef("technique_id", str, ""),
        FieldDef("effectiveness_pct", float, 0.0),
        FieldDef("regression", bool, False),
    ],
    key_field="validation_id",
)

# Backward-compatible re-exports
ValidationOutcome = AdversarialEffectivenessEngine.ValidationOutcome
DefenseCategory = AdversarialEffectivenessEngine.DefenseCategory
TrendDirection = AdversarialEffectivenessEngine.TrendDirection
AdversarialEffectivenessRecord = AdversarialEffectivenessEngine.Record
AdversarialEffectivenessAnalysis = AdversarialEffectivenessEngine.Analysis
AdversarialEffectivenessReport = AdversarialEffectivenessEngine.Report
