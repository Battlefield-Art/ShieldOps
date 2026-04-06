"""ServiceDegradationEngine — service degradation engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ServiceDegradationEngine = engine(
    "ServiceDegradationEngine",
    description="Service Degradation Engine.",
    enums={
        "degradation_level": EnumDef(
            "DegradationLevel",
            {
                "NONE": "none",
                "MINOR": "minor",
                "MODERATE": "moderate",
                "MAJOR": "major",
                "COMPLETE": "complete",
            },
        ),
        "degradation_cause": EnumDef(
            "DegradationCause",
            {
                "CAPACITY": "capacity",
                "DEPENDENCY": "dependency",
                "CONFIGURATION": "configuration",
                "INFRASTRUCTURE": "infrastructure",
                "EXTERNAL": "external",
            },
        ),
        "mitigation_action": EnumDef(
            "MitigationAction",
            {
                "SCALE": "scale",
                "FAILOVER": "failover",
                "CIRCUIT_BREAK": "circuit_break",
                "RATE_LIMIT": "rate_limit",
                "MANUAL": "manual",
            },
        ),
    },
)

# Backward-compatible re-exports
DegradationLevel = ServiceDegradationEngine.DegradationLevel
DegradationCause = ServiceDegradationEngine.DegradationCause
MitigationAction = ServiceDegradationEngine.MitigationAction
ServiceDegradationRecord = ServiceDegradationEngine.Record
ServiceDegradationAnalysis = ServiceDegradationEngine.Analysis
ServiceDegradationReport = ServiceDegradationEngine.Report
