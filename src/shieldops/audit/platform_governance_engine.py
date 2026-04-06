"""PlatformGovernanceEngine — platform governance engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PlatformGovernanceEngine = engine(
    "PlatformGovernanceEngine",
    module="operations",  # uses record_item
    description="Platform Governance Engine.",
    enums={
        "governance_domain": EnumDef(
            "GovernanceDomain",
            {
                "SECURITY": "security",
                "COMPLIANCE": "compliance",
                "FINANCIAL": "financial",
                "OPERATIONAL": "operational",
                "TECHNICAL": "technical",
            },
        ),
        "governance_status": EnumDef(
            "GovernanceStatus",
            {
                "COMPLIANT": "compliant",
                "PARTIALLY_COMPLIANT": "partially_compliant",
                "NON_COMPLIANT": "non_compliant",
                "EXEMPT": "exempt",
                "PENDING": "pending",
            },
        ),
        "governance_action": EnumDef(
            "GovernanceAction",
            {
                "ENFORCE": "enforce",
                "MONITOR": "monitor",
                "AUDIT": "audit",
                "REMEDIATE": "remediate",
                "WAIVE": "waive",
            },
        ),
    },
)

# Backward-compatible re-exports
GovernanceDomain = PlatformGovernanceEngine.GovernanceDomain
GovernanceStatus = PlatformGovernanceEngine.GovernanceStatus
GovernanceAction = PlatformGovernanceEngine.GovernanceAction
PlatformGovernanceEngineRecord = PlatformGovernanceEngine.Record
PlatformGovernanceEngineAnalysis = PlatformGovernanceEngine.Analysis
PlatformGovernanceEngineReport = PlatformGovernanceEngine.Report
