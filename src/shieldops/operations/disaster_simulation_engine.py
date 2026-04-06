"""DisasterSimulationEngine — disaster simulation engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DisasterSimulationEngine = engine(
    "DisasterSimulationEngine",
    module="operations",  # uses record_item
    description="Disaster Simulation Engine.",
    enums={
        "disaster_type": EnumDef(
            "DisasterType",
            {
                "REGION_OUTAGE": "region_outage",
                "DATA_CENTER_LOSS": "data_center_loss",
                "NETWORK_PARTITION": "network_partition",
                "DATA_CORRUPTION": "data_corruption",
                "CYBER_ATTACK": "cyber_attack",
            },
        ),
        "simulation_phase": EnumDef(
            "SimulationPhase",
            {
                "SETUP": "setup",
                "INJECTION": "injection",
                "OBSERVATION": "observation",
                "RECOVERY": "recovery",
                "VALIDATION": "validation",
            },
        ),
        "recovery_verdict": EnumDef(
            "RecoveryVerdict",
            {
                "SUCCESSFUL": "successful",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "TIMEOUT": "timeout",
                "UNTESTED": "untested",
            },
        ),
    },
)

# Backward-compatible re-exports
DisasterType = DisasterSimulationEngine.DisasterType
SimulationPhase = DisasterSimulationEngine.SimulationPhase
RecoveryVerdict = DisasterSimulationEngine.RecoveryVerdict
DisasterSimulationRecord = DisasterSimulationEngine.Record
DisasterSimulationAnalysis = DisasterSimulationEngine.Analysis
DisasterSimulationReport = DisasterSimulationEngine.Report
