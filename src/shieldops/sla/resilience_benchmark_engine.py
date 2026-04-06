"""ResilienceBenchmarkEngine — resilience benchmark engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ResilienceBenchmarkEngine = engine(
    "ResilienceBenchmarkEngine",
    description="Resilience Benchmark Engine.",
    enums={
        "benchmark_category": EnumDef(
            "BenchmarkCategory",
            {
                "RECOVERY_TIME": "recovery_time",
                "FAILOVER_SPEED": "failover_speed",
                "DATA_DURABILITY": "data_durability",
                "BLAST_RADIUS": "blast_radius",
                "GRACEFUL_DEGRADATION": "graceful_degradation",
            },
        ),
        "maturity_level": EnumDef(
            "MaturityLevel",
            {
                "INITIAL": "initial",
                "DEVELOPING": "developing",
                "DEFINED": "defined",
                "MANAGED": "managed",
                "OPTIMIZING": "optimizing",
            },
        ),
        "comparison_baseline": EnumDef(
            "ComparisonBaseline",
            {
                "INDUSTRY": "industry",
                "INTERNAL": "internal",
                "PEER_GROUP": "peer_group",
                "HISTORICAL": "historical",
                "TARGET": "target",
            },
        ),
    },
)

# Backward-compatible re-exports
BenchmarkCategory = ResilienceBenchmarkEngine.BenchmarkCategory
MaturityLevel = ResilienceBenchmarkEngine.MaturityLevel
ComparisonBaseline = ResilienceBenchmarkEngine.ComparisonBaseline
ResilienceBenchmarkRecord = ResilienceBenchmarkEngine.Record
ResilienceBenchmarkAnalysis = ResilienceBenchmarkEngine.Analysis
ResilienceBenchmarkReport = ResilienceBenchmarkEngine.Report
