"""Cross Team Automation Orchestrator cross-team automation orchestration and workflow coordin..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

CrossTeamAutomationOrchestrator = engine(
    "CrossTeamAutomationOrchestrator",
    description="Cross Team Automation Orchestrator cross-team automation orchestration and...",
    enums={
        "team_domain": EnumDef(
            "TeamDomain",
            {
                "SRE": "sre",
                "SECURITY": "security",
                "DEVELOPMENT": "development",
                "DATA": "data",
                "PLATFORM": "platform",
            },
        ),
        "orchestration_mode": EnumDef(
            "OrchestrationMode",
            {
                "SEQUENTIAL": "sequential",
                "PARALLEL": "parallel",
                "CONDITIONAL": "conditional",
                "EVENT_DRIVEN": "event_driven",
                "HYBRID": "hybrid",
            },
        ),
        "orchestration_status": EnumDef(
            "OrchestrationStatus",
            {
                "COMPLETED": "completed",
                "IN_PROGRESS": "in_progress",
                "BLOCKED": "blocked",
                "FAILED": "failed",
                "CANCELLED": "cancelled",
            },
        ),
    },
)

# Backward-compatible re-exports
TeamDomain = CrossTeamAutomationOrchestrator.TeamDomain
OrchestrationMode = CrossTeamAutomationOrchestrator.OrchestrationMode
OrchestrationStatus = CrossTeamAutomationOrchestrator.OrchestrationStatus
OrchestrationRecord = CrossTeamAutomationOrchestrator.Record
OrchestrationAnalysis = CrossTeamAutomationOrchestrator.Analysis
CrossTeamAutomationReport = CrossTeamAutomationOrchestrator.Report
