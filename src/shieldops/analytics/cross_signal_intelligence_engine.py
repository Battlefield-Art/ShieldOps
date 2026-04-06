"""CrossSignalIntelligenceEngine — cross signal intelligence engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

CrossSignalIntelligenceEngine = engine(
    "CrossSignalIntelligenceEngine",
    module="operations",  # uses record_item
    description="Cross Signal Intelligence Engine.",
    enums={
        "signal_domain": EnumDef(
            "SignalDomain",
            {
                "METRICS": "metrics",
                "LOGS": "logs",
                "TRACES": "traces",
                "EVENTS": "events",
                "ALERTS": "alerts",
            },
        ),
        "correlation_method": EnumDef(
            "CorrelationMethod",
            {
                "TEMPORAL": "temporal",
                "CAUSAL": "causal",
                "STATISTICAL": "statistical",
                "ML_BASED": "ml_based",
                "GRAPH": "graph",
            },
        ),
        "insight_priority": EnumDef(
            "InsightPriority",
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
SignalDomain = CrossSignalIntelligenceEngine.SignalDomain
CorrelationMethod = CrossSignalIntelligenceEngine.CorrelationMethod
InsightPriority = CrossSignalIntelligenceEngine.InsightPriority
CrossSignalIntelligenceEngineRecord = CrossSignalIntelligenceEngine.Record
CrossSignalIntelligenceEngineAnalysis = CrossSignalIntelligenceEngine.Analysis
CrossSignalIntelligenceEngineReport = CrossSignalIntelligenceEngine.Report
