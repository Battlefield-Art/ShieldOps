"""Agent Performance Benchmark Engine — multi-dimensional agent benchmarking."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AgentPerformanceBenchmarkEngine = engine(
    "AgentPerformanceBenchmarkEngine",
    description="Benchmark agent performance across accuracy, latency, cost, reliability.",
    enums={
        "dimension": EnumDef(
            "BenchmarkDimension",
            {
                "ACCURACY": "accuracy",
                "LATENCY": "latency",
                "COST_EFFICIENCY": "cost_efficiency",
                "RELIABILITY": "reliability",
            },
        ),
        "baseline": EnumDef(
            "BenchmarkBaseline",
            {
                "INDUSTRY_STANDARD": "industry_standard",
                "HISTORICAL_BEST": "historical_best",
                "PEER_COMPARISON": "peer_comparison",
                "TARGET_SLA": "target_sla",
            },
        ),
        "trend": EnumDef(
            "PerformanceTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "VOLATILE": "volatile",
            },
        ),
    },
    key_field="agent_id",
)

# Backward-compatible re-exports
BenchmarkDimension = AgentPerformanceBenchmarkEngine.BenchmarkDimension
BenchmarkBaseline = AgentPerformanceBenchmarkEngine.BenchmarkBaseline
PerformanceTrend = AgentPerformanceBenchmarkEngine.PerformanceTrend
BenchmarkRecord = AgentPerformanceBenchmarkEngine.Record
BenchmarkAnalysis = AgentPerformanceBenchmarkEngine.Analysis
BenchmarkReport = AgentPerformanceBenchmarkEngine.Report
