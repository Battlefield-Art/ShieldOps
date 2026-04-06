"""Intelligent Root Cause Ranker — root cause ranking and correlation."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IntelligentRootCauseRanker = engine(
    "IntelligentRootCauseRanker",
    description="Intelligent Root Cause Ranker for root cause ranking and correlation.",
    enums={
        "cause_category": EnumDef(
            "CauseCategory",
            {
                "INFRASTRUCTURE": "infrastructure",
                "APPLICATION": "application",
                "CONFIGURATION": "configuration",
                "EXTERNAL": "external",
            },
        ),
        "ranking_method": EnumDef(
            "RankingMethod",
            {
                "BAYESIAN": "bayesian",
                "FREQUENCY": "frequency",
                "RECENCY": "recency",
                "IMPACT": "impact",
            },
        ),
        "confidence_level": EnumDef(
            "ConfidenceLevel",
            {
                "DEFINITIVE": "definitive",
                "PROBABLE": "probable",
                "POSSIBLE": "possible",
                "SPECULATIVE": "speculative",
            },
        ),
    },
)

# Backward-compatible re-exports
CauseCategory = IntelligentRootCauseRanker.CauseCategory
RankingMethod = IntelligentRootCauseRanker.RankingMethod
ConfidenceLevel = IntelligentRootCauseRanker.ConfidenceLevel
RootCauseRecord = IntelligentRootCauseRanker.Record
RootCauseAnalysis = IntelligentRootCauseRanker.Analysis
IntelligentRootCauseReport = IntelligentRootCauseRanker.Report
