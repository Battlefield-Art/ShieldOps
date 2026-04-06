"""ReportGenerationEngine -- generate reports."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ReportGenerationEngine = engine(
    "ReportGenerationEngine",
    module="operations",  # uses record_item
    description="Generate and distribute reports.",
    enums={
        "template": EnumDef(
            "ReportTemplate",
            {
                "EXECUTIVE": "executive",
                "TECHNICAL": "technical",
                "COMPLIANCE": "compliance",
                "INCIDENT": "incident",
                "SCORECARD": "scorecard",
            },
        ),
        "status": EnumDef(
            "GenerationStatus",
            {
                "PENDING": "pending",
                "GENERATING": "generating",
                "COMPLETED": "completed",
                "FAILED": "failed",
            },
        ),
        "channel": EnumDef(
            "DistributionChannel",
            {
                "EMAIL": "email",
                "SLACK": "slack",
                "DASHBOARD": "dashboard",
                "API": "api",
                "PDF": "pdf",
            },
        ),
    },
    record_fields=[
        FieldDef("recipient", str, ""),
    ],
)

# Backward-compatible re-exports
ReportTemplate = ReportGenerationEngine.ReportTemplate
GenerationStatus = ReportGenerationEngine.GenerationStatus
DistributionChannel = ReportGenerationEngine.DistributionChannel
ReportGenerationRecord = ReportGenerationEngine.Record
ReportGenerationAnalysis = ReportGenerationEngine.Analysis
ReportGenerationReport = ReportGenerationEngine.Report
