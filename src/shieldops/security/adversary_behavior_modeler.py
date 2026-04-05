"""AdversaryBehaviorModeler — adversary behavior modeler."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AdversaryBehaviorModeler = engine(
    "AdversaryBehaviorModeler",
    module="operations",  # uses record_item
    description="Adversary Behavior Modeler.",
    enums={
        "behavior_type": EnumDef(
            "BehaviorType",
            {
                "RECONNAISSANCE": "reconnaissance",
                "WEAPONIZATION": "weaponization",
                "DELIVERY": "delivery",
                "EXPLOITATION": "exploitation",
                "INSTALLATION": "installation",
            },
        ),
        "model_accuracy": EnumDef(
            "ModelAccuracy",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "EXPERIMENTAL": "experimental",
                "UNVALIDATED": "unvalidated",
            },
        ),
        "actor_sophistication": EnumDef(
            "ActorSophistication",
            {
                "NATION_STATE": "nation_state",
                "ORGANIZED_CRIME": "organized_crime",
                "HACKTIVIST": "hacktivist",
                "INSIDER": "insider",
                "SCRIPT_KIDDIE": "script_kiddie",
            },
        ),
    },
)

# Backward-compatible re-exports
BehaviorType = AdversaryBehaviorModeler.BehaviorType
ModelAccuracy = AdversaryBehaviorModeler.ModelAccuracy
ActorSophistication = AdversaryBehaviorModeler.ActorSophistication
AdversaryBehaviorModelerRecord = AdversaryBehaviorModeler.Record
AdversaryBehaviorModelerAnalysis = AdversaryBehaviorModeler.Analysis
AdversaryBehaviorModelerReport = AdversaryBehaviorModeler.Report
