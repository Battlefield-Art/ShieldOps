"""DeveloperProductivityEngine Developer productivity measurement, flow state tracking, DORA-a..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DeveloperProductivityEngine = engine(
    "DeveloperProductivityEngine",
    description="Developer productivity measurement and engineering effectiveness.",
    enums={
        "productivity_metric": EnumDef(
            "ProductivityMetric",
            {
                "CYCLE_TIME": "cycle_time",
                "CODE_REVIEW_TIME": "code_review_time",
                "DEPLOY_FREQUENCY": "deploy_frequency",
                "CONTEXT_SWITCHES": "context_switches",
                "FLOW_STATE_HOURS": "flow_state_hours",
            },
        ),
        "productivity_level": EnumDef(
            "ProductivityLevel",
            {
                "ELITE": "elite",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNKNOWN": "unknown",
            },
        ),
        "productivity_source": EnumDef(
            "ProductivitySource",
            {
                "GIT": "git",
                "CI_CD": "ci_cd",
                "JIRA": "jira",
                "IDE_TELEMETRY": "ide_telemetry",
                "SURVEY": "survey",
            },
        ),
    },
)

# Backward-compatible re-exports
ProductivityMetric = DeveloperProductivityEngine.ProductivityMetric
ProductivityLevel = DeveloperProductivityEngine.ProductivityLevel
ProductivitySource = DeveloperProductivityEngine.ProductivitySource
DeveloperProductivityRecord = DeveloperProductivityEngine.Record
DeveloperProductivityAnalysis = DeveloperProductivityEngine.Analysis
DeveloperProductivityReport = DeveloperProductivityEngine.Report
