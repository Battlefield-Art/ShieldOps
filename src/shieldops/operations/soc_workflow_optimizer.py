"""Soc Workflow Optimizer — SOC workflow optimization and analyst efficiency."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SocWorkflowOptimizer = engine(
    "SocWorkflowOptimizer",
    description="Soc Workflow Optimizer — SOC workflow optimization and analyst efficiency.",
    enums={
        "workflow_phase": EnumDef(
            "WorkflowPhase",
            {
                "TRIAGE": "triage",
                "INVESTIGATION": "investigation",
                "CONTAINMENT": "containment",
                "REMEDIATION": "remediation",
                "CLOSURE": "closure",
            },
        ),
        "optimization_area": EnumDef(
            "OptimizationArea",
            {
                "AUTOMATION": "automation",
                "ROUTING": "routing",
                "PRIORITIZATION": "prioritization",
                "ENRICHMENT": "enrichment",
                "HANDOFF": "handoff",
            },
        ),
        "workflow_efficiency": EnumDef(
            "WorkflowEfficiency",
            {
                "OPTIMAL": "optimal",
                "GOOD": "good",
                "NEEDS_IMPROVEMENT": "needs_improvement",
                "POOR": "poor",
                "BLOCKED": "blocked",
            },
        ),
    },
)

# Backward-compatible re-exports
WorkflowPhase = SocWorkflowOptimizer.WorkflowPhase
OptimizationArea = SocWorkflowOptimizer.OptimizationArea
WorkflowEfficiency = SocWorkflowOptimizer.WorkflowEfficiency
WorkflowRecord = SocWorkflowOptimizer.Record
WorkflowAnalysis = SocWorkflowOptimizer.Analysis
SocWorkflowReport = SocWorkflowOptimizer.Report
