"""Autonomous Healing Orchestrator — autonomous self-healing orchestration for infrastructure."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutonomousHealingOrchestrator = engine(
    "AutonomousHealingOrchestrator",
    description="Autonomous Healing Orchestrator autonomous self-healing orchestration for i...",
    enums={
        "healing_action": EnumDef(
            "HealingAction",
            {
                "RESTART": "restart",
                "FAILOVER": "failover",
                "REPAIR": "repair",
                "RECONFIGURE": "reconfigure",
                "REPLACE": "replace",
            },
        ),
        "healing_trigger": EnumDef(
            "HealingTrigger",
            {
                "HEALTH_CHECK": "health_check",
                "ANOMALY": "anomaly",
                "THRESHOLD": "threshold",
                "DEPENDENCY_FAILURE": "dependency_failure",
                "MANUAL": "manual",
            },
        ),
        "healing_outcome": EnumDef(
            "HealingOutcome",
            {
                "HEALED": "healed",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "ESCALATED": "escalated",
                "DEFERRED": "deferred",
            },
        ),
    },
)

# Backward-compatible re-exports
HealingAction = AutonomousHealingOrchestrator.HealingAction
HealingTrigger = AutonomousHealingOrchestrator.HealingTrigger
HealingOutcome = AutonomousHealingOrchestrator.HealingOutcome
HealingRecord = AutonomousHealingOrchestrator.Record
HealingAnalysis = AutonomousHealingOrchestrator.Analysis
AutonomousHealingReport = AutonomousHealingOrchestrator.Report
