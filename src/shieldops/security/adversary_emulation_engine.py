"""Adversary Emulation Engine generate emulation plans, evaluate detection coverage, score def..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AdversaryEmulationEngine = engine(
    "AdversaryEmulationEngine",
    description="Generate emulation plans, evaluate detection coverage, and score defense re...",
    enums={
        "framework": EnumDef(
            "EmulationFramework",
            {
                "MITRE_ATTACK": "mitre_attack",
                "CYBER_KILL_CHAIN": "cyber_kill_chain",
                "DIAMOND_MODEL": "diamond_model",
                "CUSTOM": "custom",
            },
        ),
        "phase": EnumDef(
            "EmulationPhase",
            {
                "RECON": "recon",
                "WEAPONIZE": "weaponize",
                "DELIVER": "deliver",
                "EXPLOIT": "exploit",
                "INSTALL": "install",
                "COMMAND": "command",
                "ACTIONS": "actions",
            },
        ),
        "outcome": EnumDef(
            "EmulationOutcome",
            {
                "DETECTED": "detected",
                "BLOCKED": "blocked",
                "EVADED": "evaded",
                "PARTIAL": "partial",
            },
        ),
    },
    record_fields=[
        FieldDef("detection_rate", float, 0.0),
    ],
    score_field="readiness_score",
    key_field="emulation_id",
)

# Backward-compatible re-exports
EmulationFramework = AdversaryEmulationEngine.EmulationFramework
EmulationPhase = AdversaryEmulationEngine.EmulationPhase
EmulationOutcome = AdversaryEmulationEngine.EmulationOutcome
EmulationRecord = AdversaryEmulationEngine.Record
EmulationAnalysis = AdversaryEmulationEngine.Analysis
EmulationReport = AdversaryEmulationEngine.Report
