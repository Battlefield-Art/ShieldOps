"""Security Operations Cost Analyzer — security operations cost analysis and ROI tracking."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityOperationsCostAnalyzer = engine(
    "SecurityOperationsCostAnalyzer",
    description="Security Operations Cost Analyzer — security operations cost analysis and R...",
    enums={
        "cost_domain": EnumDef(
            "CostDomain",
            {
                "PERSONNEL": "personnel",
                "TOOLING": "tooling",
                "INFRASTRUCTURE": "infrastructure",
                "TRAINING": "training",
                "INCIDENT": "incident",
            },
        ),
        "cost_source": EnumDef(
            "CostSource",
            {
                "BILLING_API": "billing_api",
                "TIME_TRACKING": "time_tracking",
                "LICENSE_MANAGER": "license_manager",
                "ESTIMATED": "estimated",
                "CUSTOM": "custom",
            },
        ),
        "roi_level": EnumDef(
            "ROILevel",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "AVERAGE": "average",
                "POOR": "poor",
                "NEGATIVE": "negative",
            },
        ),
    },
)

# Backward-compatible re-exports
CostDomain = SecurityOperationsCostAnalyzer.CostDomain
CostSource = SecurityOperationsCostAnalyzer.CostSource
ROILevel = SecurityOperationsCostAnalyzer.ROILevel
SecOpsCostRecord = SecurityOperationsCostAnalyzer.Record
SecOpsCostAnalysis = SecurityOperationsCostAnalyzer.Analysis
SecurityOperationsCostReport = SecurityOperationsCostAnalyzer.Report
