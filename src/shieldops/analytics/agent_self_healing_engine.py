"""Agent Self-Healing Engine — track and optimize agent automatic recovery."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentSelfHealingEngine = engine(
    "AgentSelfHealingEngine",
    description="Track and optimize agent self-healing, circuit breaking, and degradation re...",
    enums={
        "healing_action": EnumDef(
            "HealingAction",
            {
                "RESTART": "restart",
                "FALLBACK": "fallback",
                "CIRCUIT_BREAK": "circuit_break",
                "DEGRADE_GRACEFULLY": "degrade_gracefully",
            },
        ),
        "failure_mode": EnumDef(
            "FailureMode",
            {
                "TIMEOUT": "timeout",
                "OOM": "oom",
                "API_ERROR": "api_error",
                "INVALID_STATE": "invalid_state",
                "DEPENDENCY_FAILURE": "dependency_failure",
            },
        ),
        "recovery_status": EnumDef(
            "RecoveryStatus",
            {
                "RECOVERED": "recovered",
                "DEGRADED": "degraded",
                "FAILED": "failed",
                "MANUAL_INTERVENTION": "manual_intervention",
            },
        ),
    },
    record_fields=[
        FieldDef("recovery_time_ms", float, 0.0),
        FieldDef("agent_id", str, ""),
    ],
)

# Backward-compatible re-exports
HealingAction = AgentSelfHealingEngine.HealingAction
FailureMode = AgentSelfHealingEngine.FailureMode
RecoveryStatus = AgentSelfHealingEngine.RecoveryStatus
HealingRecord = AgentSelfHealingEngine.Record
HealingAnalysis = AgentSelfHealingEngine.Analysis
HealingReport = AgentSelfHealingEngine.Report
