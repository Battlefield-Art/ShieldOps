"""Trace Sampling Optimizer — intelligent trace sampling optimization for cost and coverage."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

TraceSamplingOptimizer = engine(
    "TraceSamplingOptimizer",
    description="Trace Sampling Optimizer — intelligent trace sampling optimization for cost...",
    enums={
        "sampling_strategy": EnumDef(
            "SamplingStrategy",
            {
                "HEAD_BASED": "head_based",
                "TAIL_BASED": "tail_based",
                "PRIORITY": "priority",
                "ADAPTIVE": "adaptive",
                "HYBRID": "hybrid",
            },
        ),
        "sampling_target": EnumDef(
            "SamplingTarget",
            {
                "COST_REDUCTION": "cost_reduction",
                "ERROR_CAPTURE": "error_capture",
                "LATENCY_FOCUS": "latency_focus",
                "COVERAGE": "coverage",
                "BALANCED": "balanced",
            },
        ),
        "sampling_efficiency": EnumDef(
            "SamplingEfficiency",
            {
                "OPTIMAL": "optimal",
                "ACCEPTABLE": "acceptable",
                "INEFFICIENT": "inefficient",
                "WASTEFUL": "wasteful",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
SamplingStrategy = TraceSamplingOptimizer.SamplingStrategy
SamplingTarget = TraceSamplingOptimizer.SamplingTarget
SamplingEfficiency = TraceSamplingOptimizer.SamplingEfficiency
SamplingRecord = TraceSamplingOptimizer.Record
SamplingAnalysis = TraceSamplingOptimizer.Analysis
TraceSamplingReport = TraceSamplingOptimizer.Report
