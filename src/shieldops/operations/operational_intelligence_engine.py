"""Operational Intelligence Engine — operational intelligence with cross-system insights."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

OperationalIntelligenceEngine = engine(
    "OperationalIntelligenceEngine",
    description="Operational Intelligence Engine — operational intelligence with cross-syste...",
    enums={
        "intel_type": EnumDef(
            "IntelType",
            {
                "TREND": "trend",
                "ANOMALY": "anomaly",
                "PREDICTION": "prediction",
                "RECOMMENDATION": "recommendation",
                "ROOT_CAUSE": "root_cause",
            },
        ),
        "intel_source": EnumDef(
            "IntelSource",
            {
                "MONITORING": "monitoring",
                "INCIDENTS": "incidents",
                "CHANGES": "changes",
                "CAPACITY": "capacity",
                "COSTS": "costs",
            },
        ),
        "intel_relevance": EnumDef(
            "IntelRelevance",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFORMATIONAL": "informational",
            },
        ),
    },
)

# Backward-compatible re-exports
IntelType = OperationalIntelligenceEngine.IntelType
IntelSource = OperationalIntelligenceEngine.IntelSource
IntelRelevance = OperationalIntelligenceEngine.IntelRelevance
OpIntelRecord = OperationalIntelligenceEngine.Record
OpIntelAnalysis = OperationalIntelligenceEngine.Analysis
OperationalIntelligenceReport = OperationalIntelligenceEngine.Report
