"""Ml Driven Runbook Generator — ML-driven runbook generation from incident patterns."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

MlDrivenRunbookGenerator = engine(
    "MlDrivenRunbookGenerator",
    description="Ml Driven Runbook Generator — ML-driven runbook generation from incident pa...",
    enums={
        "runbook_type": EnumDef(
            "RunbookType",
            {
                "DIAGNOSTIC": "diagnostic",
                "REMEDIATION": "remediation",
                "ESCALATION": "escalation",
                "RECOVERY": "recovery",
                "VERIFICATION": "verification",
            },
        ),
        "generation_source": EnumDef(
            "GenerationSource",
            {
                "INCIDENT_HISTORY": "incident_history",
                "EXPERT_KNOWLEDGE": "expert_knowledge",
                "ML_MODEL": "ml_model",
                "TEMPLATE": "template",
                "HYBRID": "hybrid",
            },
        ),
        "runbook_quality": EnumDef(
            "RunbookQuality",
            {
                "PRODUCTION_READY": "production_ready",
                "REVIEW_NEEDED": "review_needed",
                "DRAFT": "draft",
                "EXPERIMENTAL": "experimental",
                "DEPRECATED": "deprecated",
            },
        ),
    },
)

# Backward-compatible re-exports
RunbookType = MlDrivenRunbookGenerator.RunbookType
GenerationSource = MlDrivenRunbookGenerator.GenerationSource
RunbookQuality = MlDrivenRunbookGenerator.RunbookQuality
RunbookGenRecord = MlDrivenRunbookGenerator.Record
RunbookGenAnalysis = MlDrivenRunbookGenerator.Analysis
MlDrivenRunbookReport = MlDrivenRunbookGenerator.Report
