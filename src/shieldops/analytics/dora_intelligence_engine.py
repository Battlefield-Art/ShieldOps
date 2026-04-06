"""Dora Intelligence Engine — DORA metrics intelligence and engineering effectiveness."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DORAIntelligenceEngine = engine(
    "DORAIntelligenceEngine",
    description="Dora Intelligence Engine — DORA metrics intelligence and engineering effect...",
    enums={
        "dora_metric": EnumDef(
            "DORAMetric",
            {
                "DEPLOYMENT_FREQUENCY": "deployment_frequency",
                "LEAD_TIME": "lead_time",
                "CHANGE_FAILURE_RATE": "change_failure_rate",
                "MTTR": "mttr",
                "RELIABILITY": "reliability",
            },
        ),
        "dora_source": EnumDef(
            "DORASource",
            {
                "CI_CD_PIPELINE": "ci_cd_pipeline",
                "GIT_HISTORY": "git_history",
                "INCIDENT_TRACKER": "incident_tracker",
                "DEPLOYMENT_LOG": "deployment_log",
                "CUSTOM": "custom",
            },
        ),
        "dora_performance": EnumDef(
            "DORAPerformance",
            {
                "ELITE": "elite",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
DORAMetric = DORAIntelligenceEngine.DORAMetric
DORASource = DORAIntelligenceEngine.DORASource
DORAPerformance = DORAIntelligenceEngine.DORAPerformance
DORARecord = DORAIntelligenceEngine.Record
DORAAnalysis = DORAIntelligenceEngine.Analysis
DORAIntelligenceReport = DORAIntelligenceEngine.Report
