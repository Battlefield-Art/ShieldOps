"""ChaosGameDayEngine — chaos game day engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ChaosGameDayEngine = engine(
    "ChaosGameDayEngine",
    module="operations",  # uses record_item
    description="Chaos Game Day Engine.",
    enums={
        "game_day_phase": EnumDef(
            "GameDayPhase",
            {
                "PLANNING": "planning",
                "EXECUTION": "execution",
                "OBSERVATION": "observation",
                "ANALYSIS": "analysis",
                "RETROSPECTIVE": "retrospective",
            },
        ),
        "scenario_type": EnumDef(
            "ScenarioType",
            {
                "SERVICE_OUTAGE": "service_outage",
                "NETWORK_PARTITION": "network_partition",
                "RESOURCE_EXHAUSTION": "resource_exhaustion",
                "DATA_CORRUPTION": "data_corruption",
                "CASCADING_FAILURE": "cascading_failure",
            },
        ),
        "game_day_result": EnumDef(
            "GameDayResult",
            {
                "SUCCESS": "success",
                "PARTIAL": "partial",
                "FAILURE": "failure",
                "ABORTED": "aborted",
                "INCONCLUSIVE": "inconclusive",
            },
        ),
    },
)

# Backward-compatible re-exports
GameDayPhase = ChaosGameDayEngine.GameDayPhase
ScenarioType = ChaosGameDayEngine.ScenarioType
GameDayResult = ChaosGameDayEngine.GameDayResult
ChaosGameDayRecord = ChaosGameDayEngine.Record
ChaosGameDayAnalysis = ChaosGameDayEngine.Analysis
ChaosGameDayReport = ChaosGameDayEngine.Report
