"""Workflow Intelligence Engine — workflow analysis and optimization."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

WorkflowIntelligenceEngine = engine(
    "WorkflowIntelligenceEngine",
    module="operations",  # uses record_item
    description="Workflow Intelligence Engine for workflow analysis and optimization.",
    enums={
        "workflow_complexity": EnumDef(
            "WorkflowComplexity",
            {
                "LINEAR": "linear",
                "BRANCHING": "branching",
                "PARALLEL": "parallel",
                "ADAPTIVE": "adaptive",
            },
        ),
        "execution_status": EnumDef(
            "ExecutionStatus",
            {
                "PENDING": "pending",
                "RUNNING": "running",
                "COMPLETED": "completed",
                "FAILED": "failed",
            },
        ),
        "optimization_goal": EnumDef(
            "OptimizationGoal",
            {
                "SPEED": "speed",
                "RELIABILITY": "reliability",
                "COST": "cost",
                "COVERAGE": "coverage",
            },
        ),
    },
)

# Backward-compatible re-exports
WorkflowComplexity = WorkflowIntelligenceEngine.WorkflowComplexity
ExecutionStatus = WorkflowIntelligenceEngine.ExecutionStatus
OptimizationGoal = WorkflowIntelligenceEngine.OptimizationGoal
WorkflowRecord = WorkflowIntelligenceEngine.Record
WorkflowAnalysis = WorkflowIntelligenceEngine.Analysis
WorkflowIntelligenceReport = WorkflowIntelligenceEngine.Report
