"""Chaos Intelligence Engine — chaos engineering intelligence with experiment insights."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ChaosIntelligenceEngine = engine(
    "ChaosIntelligenceEngine",
    description="Chaos Intelligence Engine — chaos engineering intelligence with experiment...",
    enums={
        "experiment_type": EnumDef(
            "ExperimentType",
            {
                "LATENCY_INJECTION": "latency_injection",
                "FAILURE_INJECTION": "failure_injection",
                "RESOURCE_STRESS": "resource_stress",
                "NETWORK_PARTITION": "network_partition",
                "DNS_FAILURE": "dns_failure",
            },
        ),
        "chaos_source": EnumDef(
            "ChaosSource",
            {
                "LITMUS": "litmus",
                "CHAOS_MONKEY": "chaos_monkey",
                "GREMLIN": "gremlin",
                "CUSTOM": "custom",
                "GAME_DAY": "game_day",
            },
        ),
        "experiment_outcome": EnumDef(
            "ExperimentOutcome",
            {
                "RESILIENT": "resilient",
                "DEGRADED": "degraded",
                "FAILED": "failed",
                "CASCADING": "cascading",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
ExperimentType = ChaosIntelligenceEngine.ExperimentType
ChaosSource = ChaosIntelligenceEngine.ChaosSource
ExperimentOutcome = ChaosIntelligenceEngine.ExperimentOutcome
ChaosIntelRecord = ChaosIntelligenceEngine.Record
ChaosIntelAnalysis = ChaosIntelligenceEngine.Analysis
ChaosIntelligenceReport = ChaosIntelligenceEngine.Report
