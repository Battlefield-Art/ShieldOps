"""Intelligent Audit Planner — intelligent audit planning and optimization."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IntelligentAuditPlanner = engine(
    "IntelligentAuditPlanner",
    description="Intelligent Audit Planner for audit planning and optimization.",
    enums={
        "audit_scope": EnumDef(
            "AuditScope",
            {
                "FULL": "full",
                "TARGETED": "targeted",
                "CONTINUOUS": "continuous",
                "SAMPLING": "sampling",
            },
        ),
        "audit_priority": EnumDef(
            "AuditPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "planning_horizon": EnumDef(
            "PlanningHorizon",
            {
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "QUARTERLY": "quarterly",
                "ANNUAL": "annual",
            },
        ),
    },
)

# Backward-compatible re-exports
AuditScope = IntelligentAuditPlanner.AuditScope
AuditPriority = IntelligentAuditPlanner.AuditPriority
PlanningHorizon = IntelligentAuditPlanner.PlanningHorizon
AuditPlanRecord = IntelligentAuditPlanner.Record
AuditPlanAnalysis = IntelligentAuditPlanner.Analysis
IntelligentAuditPlannerReport = IntelligentAuditPlanner.Report
