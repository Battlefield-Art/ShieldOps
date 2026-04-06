"""ResilienceDebtEngine — resilience debt engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ResilienceDebtEngine = engine(
    "ResilienceDebtEngine",
    description="Resilience Debt Engine.",
    enums={
        "debt_category": EnumDef(
            "DebtCategory",
            {
                "MISSING_REDUNDANCY": "missing_redundancy",
                "UNTESTED_FAILOVER": "untested_failover",
                "STALE_RUNBOOK": "stale_runbook",
                "NO_CHAOS_TESTING": "no_chaos_testing",
                "SINGLE_POINT_OF_FAILURE": "single_point_of_failure",
            },
        ),
        "debt_priority": EnumDef(
            "DebtPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "DEFERRED": "deferred",
            },
        ),
        "remediation_status": EnumDef(
            "RemediationStatus",
            {
                "OPEN": "open",
                "IN_PROGRESS": "in_progress",
                "RESOLVED": "resolved",
                "ACCEPTED": "accepted",
                "WONT_FIX": "wont_fix",
            },
        ),
    },
)

# Backward-compatible re-exports
DebtCategory = ResilienceDebtEngine.DebtCategory
DebtPriority = ResilienceDebtEngine.DebtPriority
RemediationStatus = ResilienceDebtEngine.RemediationStatus
ResilienceDebtRecord = ResilienceDebtEngine.Record
ResilienceDebtAnalysis = ResilienceDebtEngine.Analysis
ResilienceDebtReport = ResilienceDebtEngine.Report
