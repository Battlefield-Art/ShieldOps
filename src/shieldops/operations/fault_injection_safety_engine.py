"""Fault Injection Safety Engine — track fault injection safety and blast radius."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

FaultInjectionSafetyEngine = engine(
    "FaultInjectionSafetyEngine",
    description="Track fault injection safety gates and blast radius compliance.",
    enums={
        "safety_gate": EnumDef(
            "SafetyGate",
            {
                "PRE_CHECK": "pre_check",
                "CANARY": "canary",
                "ROLLBACK_READY": "rollback_ready",
                "SLO_GUARD": "slo_guard",
                "BLAST_RADIUS": "blast_radius",
            },
        ),
        "gate_outcome": EnumDef(
            "GateOutcome",
            {
                "PASSED": "passed",
                "FAILED": "failed",
                "BYPASSED": "bypassed",
                "TIMEOUT": "timeout",
                "NOT_APPLICABLE": "not_applicable",
            },
        ),
        "rollback_reason": EnumDef(
            "RollbackReason",
            {
                "SLO_BREACH": "slo_breach",
                "TIMEOUT": "timeout",
                "MANUAL": "manual",
                "CASCADING_FAILURE": "cascading_failure",
                "SAFETY_GATE": "safety_gate",
            },
        ),
    },
    record_fields=[
        FieldDef("service_id", str, ""),
        FieldDef("blast_radius_actual", int, 0),
        FieldDef("blast_radius_limit", int, 0),
        FieldDef("slo_impact_pct", float, 0.0),
        FieldDef("rollback_triggered", bool, False),
        FieldDef("description", str, ""),
    ],
    key_field="experiment_id",
)

# Backward-compatible re-exports
SafetyGate = FaultInjectionSafetyEngine.SafetyGate
GateOutcome = FaultInjectionSafetyEngine.GateOutcome
RollbackReason = FaultInjectionSafetyEngine.RollbackReason
FaultInjectionSafetyRecord = FaultInjectionSafetyEngine.Record
FaultInjectionSafetyAnalysis = FaultInjectionSafetyEngine.Analysis
FaultInjectionSafetyReport = FaultInjectionSafetyEngine.Report
