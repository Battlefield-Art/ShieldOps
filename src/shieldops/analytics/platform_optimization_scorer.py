"""Platform Optimization Scorer platform optimization scoring across reliability, cost, and pe..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PlatformOptimizationScorer = engine(
    "PlatformOptimizationScorer",
    description="Platform Optimization Scorer platform optimization scoring across reliabili...",
    enums={
        "optimization_domain": EnumDef(
            "OptimizationDomain",
            {
                "RELIABILITY": "reliability",
                "PERFORMANCE": "performance",
                "COST": "cost",
                "SECURITY": "security",
                "SCALABILITY": "scalability",
            },
        ),
        "scoring_source": EnumDef(
            "ScoringSource",
            {
                "METRIC_ANALYSIS": "metric_analysis",
                "BENCHMARK": "benchmark",
                "BEST_PRACTICE": "best_practice",
                "PEER_COMPARISON": "peer_comparison",
                "CUSTOM": "custom",
            },
        ),
        "optimization_grade": EnumDef(
            "OptimizationGrade",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "NEEDS_WORK": "needs_work",
                "CRITICAL": "critical",
            },
        ),
    },
)

# Backward-compatible re-exports
OptimizationDomain = PlatformOptimizationScorer.OptimizationDomain
ScoringSource = PlatformOptimizationScorer.ScoringSource
OptimizationGrade = PlatformOptimizationScorer.OptimizationGrade
PlatformScoreRecord = PlatformOptimizationScorer.Record
PlatformScoreAnalysis = PlatformOptimizationScorer.Analysis
PlatformOptimizationReport = PlatformOptimizationScorer.Report
