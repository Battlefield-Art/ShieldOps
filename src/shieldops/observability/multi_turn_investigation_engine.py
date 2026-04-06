"""Multi-Turn Investigation Engine — orchestrate multi-turn investigation flows, determine tur..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MultiTurnInvestigationEngine = engine(
    "MultiTurnInvestigationEngine",
    description="Orchestrate multi-turn investigation flows, determine turn continuation, co...",
    enums={
        "turn_phase": EnumDef(
            "TurnPhase",
            {
                "HYPOTHESIS": "hypothesis",
                "DATA_GATHERING": "data_gathering",
                "ANALYSIS": "analysis",
                "SYNTHESIS": "synthesis",
            },
        ),
        "investigation_state": EnumDef(
            "InvestigationState",
            {
                "OPEN": "open",
                "NARROWING": "narrowing",
                "VALIDATING": "validating",
                "RESOLVED": "resolved",
            },
        ),
        "turn_outcome": EnumDef(
            "TurnOutcome",
            {
                "PROGRESS": "progress",
                "DEAD_END": "dead_end",
                "BREAKTHROUGH": "breakthrough",
                "NEEDS_ESCALATION": "needs_escalation",
            },
        ),
    },
    record_fields=[
        FieldDef("information_gain", float, 0.0),
        FieldDef("turn_index", int, 0),
        FieldDef("hypothesis", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="investigation_id",
)

# Backward-compatible re-exports
TurnPhase = MultiTurnInvestigationEngine.TurnPhase
InvestigationState = MultiTurnInvestigationEngine.InvestigationState
TurnOutcome = MultiTurnInvestigationEngine.TurnOutcome
MultiTurnInvestigationRecord = MultiTurnInvestigationEngine.Record
MultiTurnInvestigationAnalysis = MultiTurnInvestigationEngine.Analysis
MultiTurnInvestigationReport = MultiTurnInvestigationEngine.Report
