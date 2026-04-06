"""TechnicalDebtIntelligence — technical debt intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

TechnicalDebtIntelligence = engine(
    "TechnicalDebtIntelligence",
    module="operations",  # uses record_item
    description="Technical Debt Intelligence.",
    enums={
        "debt_type": EnumDef(
            "DebtType",
            {
                "CODE": "code",
                "ARCHITECTURE": "architecture",
                "INFRASTRUCTURE": "infrastructure",
                "TESTING": "testing",
                "DOCUMENTATION": "documentation",
            },
        ),
        "debt_severity": EnumDef(
            "DebtSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "ACCEPTABLE": "acceptable",
            },
        ),
        "debt_trend": EnumDef(
            "DebtTrend",
            {
                "INCREASING": "increasing",
                "STABLE": "stable",
                "DECREASING": "decreasing",
                "VOLATILE": "volatile",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
DebtType = TechnicalDebtIntelligence.DebtType
DebtSeverity = TechnicalDebtIntelligence.DebtSeverity
DebtTrend = TechnicalDebtIntelligence.DebtTrend
TechnicalDebtIntelligenceRecord = TechnicalDebtIntelligence.Record
TechnicalDebtIntelligenceAnalysis = TechnicalDebtIntelligence.Analysis
TechnicalDebtIntelligenceReport = TechnicalDebtIntelligence.Report
