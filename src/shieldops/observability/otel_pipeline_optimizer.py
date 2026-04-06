"""Otel Pipeline Optimizer — OpenTelemetry pipeline optimization and efficiency."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

OtelPipelineOptimizer = engine(
    "OtelPipelineOptimizer",
    description="Otel Pipeline Optimizer — OpenTelemetry pipeline optimization and efficiency.",
    enums={
        "pipeline_component": EnumDef(
            "PipelineComponent",
            {
                "COLLECTOR": "collector",
                "PROCESSOR": "processor",
                "EXPORTER": "exporter",
                "RECEIVER": "receiver",
                "CONNECTOR": "connector",
            },
        ),
        "optimization_target": EnumDef(
            "OptimizationTarget",
            {
                "THROUGHPUT": "throughput",
                "LATENCY": "latency",
                "RESOURCE_USAGE": "resource_usage",
                "DATA_QUALITY": "data_quality",
                "COST": "cost",
            },
        ),
        "pipeline_health": EnumDef(
            "PipelineHealth",
            {
                "OPTIMAL": "optimal",
                "ACCEPTABLE": "acceptable",
                "DEGRADED": "degraded",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
PipelineComponent = OtelPipelineOptimizer.PipelineComponent
OptimizationTarget = OtelPipelineOptimizer.OptimizationTarget
PipelineHealth = OtelPipelineOptimizer.PipelineHealth
PipelineRecord = OtelPipelineOptimizer.Record
PipelineAnalysis = OtelPipelineOptimizer.Analysis
OtelPipelineReport = OtelPipelineOptimizer.Report
