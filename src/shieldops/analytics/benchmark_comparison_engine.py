"""BenchmarkComparisonEngine -- compare to benchmarks."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

BenchmarkComparisonEngine = engine(
    "BenchmarkComparisonEngine",
    description="Compare security posture to benchmarks.",
    enums={
        "source": EnumDef(
            "BenchmarkSource",
            {
                "CIS": "cis",
                "NIST": "nist",
                "INDUSTRY": "industry",
                "PEER_GROUP": "peer_group",
                "INTERNAL": "internal",
            },
        ),
        "vertical": EnumDef(
            "IndustryVertical",
            {
                "FINANCIAL": "financial",
                "HEALTHCARE": "healthcare",
                "TECHNOLOGY": "technology",
                "GOVERNMENT": "government",
                "RETAIL": "retail",
            },
        ),
        "quartile": EnumDef(
            "PerformanceQuartile",
            {
                "TOP": "top",
                "UPPER": "upper",
                "LOWER": "lower",
                "BOTTOM": "bottom",
            },
        ),
    },
    record_fields=[
        FieldDef("benchmark_value", float, 0.0),
    ],
)

# Backward-compatible re-exports
BenchmarkSource = BenchmarkComparisonEngine.BenchmarkSource
IndustryVertical = BenchmarkComparisonEngine.IndustryVertical
PerformanceQuartile = BenchmarkComparisonEngine.PerformanceQuartile
BenchmarkComparisonRecord = BenchmarkComparisonEngine.Record
BenchmarkComparisonAnalysis = BenchmarkComparisonEngine.Analysis
BenchmarkComparisonReport = BenchmarkComparisonEngine.Report
