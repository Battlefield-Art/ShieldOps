"""Smart Alert Routing Planner plan skill based routing, optimize timezone coverage, simulate..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SmartAlertRoutingPlanner = engine(
    "SmartAlertRoutingPlanner",
    module="operations",  # uses record_item
    description="Plan skill based routing, optimize timezone coverage, simulate routing scen...",
    enums={
        "routing_strategy": EnumDef(
            "RoutingStrategy",
            {
                "SKILL_BASED": "skill_based",
                "ROUND_ROBIN": "round_robin",
                "LOAD_BALANCED": "load_balanced",
                "ESCALATION": "escalation",
            },
        ),
        "coverage_gap": EnumDef(
            "CoverageGap",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
                "NONE": "none",
            },
        ),
        "simulation_result": EnumDef(
            "SimulationResult",
            {
                "OPTIMAL": "optimal",
                "ACCEPTABLE": "acceptable",
                "SUBOPTIMAL": "suboptimal",
                "FAILED": "failed",
            },
        ),
    },
    record_fields=[
        FieldDef("responder_id", str, ""),
        FieldDef("timezone", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="skill_match_score",
    key_field="route_id",
)

# Backward-compatible re-exports
RoutingStrategy = SmartAlertRoutingPlanner.RoutingStrategy
CoverageGap = SmartAlertRoutingPlanner.CoverageGap
SimulationResult = SmartAlertRoutingPlanner.SimulationResult
SmartAlertRoutingRecord = SmartAlertRoutingPlanner.Record
SmartAlertRoutingAnalysis = SmartAlertRoutingPlanner.Analysis
SmartAlertRoutingReport = SmartAlertRoutingPlanner.Report
