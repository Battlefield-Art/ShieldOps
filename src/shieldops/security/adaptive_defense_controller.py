"""AdaptiveDefenseController — adaptive defense controller."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AdaptiveDefenseController = engine(
    "AdaptiveDefenseController",
    module="operations",  # uses record_item
    description="Adaptive Defense Controller.",
    enums={
        "defense_mode": EnumDef(
            "DefenseMode",
            {
                "NORMAL": "normal",
                "ELEVATED": "elevated",
                "HIGH_ALERT": "high_alert",
                "LOCKDOWN": "lockdown",
                "RECOVERY": "recovery",
            },
        ),
        "adaptation_trigger": EnumDef(
            "AdaptationTrigger",
            {
                "THREAT_LEVEL": "threat_level",
                "ANOMALY": "anomaly",
                "INCIDENT": "incident",
                "INTELLIGENCE": "intelligence",
                "POLICY": "policy",
            },
        ),
        "response_speed": EnumDef(
            "ResponseSpeed",
            {
                "IMMEDIATE": "immediate",
                "FAST": "fast",
                "STANDARD": "standard",
                "DELIBERATE": "deliberate",
                "PLANNED": "planned",
            },
        ),
    },
)

# Backward-compatible re-exports
DefenseMode = AdaptiveDefenseController.DefenseMode
AdaptationTrigger = AdaptiveDefenseController.AdaptationTrigger
ResponseSpeed = AdaptiveDefenseController.ResponseSpeed
AdaptiveDefenseControllerRecord = AdaptiveDefenseController.Record
AdaptiveDefenseControllerAnalysis = AdaptiveDefenseController.Analysis
AdaptiveDefenseControllerReport = AdaptiveDefenseController.Report
