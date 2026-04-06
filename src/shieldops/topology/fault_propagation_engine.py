"""FaultPropagationEngine — fault propagation engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

FaultPropagationEngine = engine(
    "FaultPropagationEngine",
    module="operations",  # uses record_item
    description="Fault Propagation Engine.",
    enums={
        "propagation_path": EnumDef(
            "PropagationPath",
            {
                "UPSTREAM": "upstream",
                "DOWNSTREAM": "downstream",
                "LATERAL": "lateral",
                "CIRCULAR": "circular",
                "ISOLATED": "isolated",
            },
        ),
        "fault_type": EnumDef(
            "FaultType",
            {
                "TIMEOUT": "timeout",
                "ERROR_SPIKE": "error_spike",
                "RESOURCE_EXHAUSTION": "resource_exhaustion",
                "DATA_INCONSISTENCY": "data_inconsistency",
                "CONNECTION_FAILURE": "connection_failure",
            },
        ),
        "propagation_risk": EnumDef(
            "PropagationRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NEGLIGIBLE": "negligible",
            },
        ),
    },
)

# Backward-compatible re-exports
PropagationPath = FaultPropagationEngine.PropagationPath
FaultType = FaultPropagationEngine.FaultType
PropagationRisk = FaultPropagationEngine.PropagationRisk
FaultPropagationRecord = FaultPropagationEngine.Record
FaultPropagationAnalysis = FaultPropagationEngine.Analysis
FaultPropagationReport = FaultPropagationEngine.Report
