"""Vulnerability Remediation Analytics — measure MTTR and risk reduction."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

VulnRemediationAnalytics = engine(
    "VulnRemediationAnalytics",
    description="Measure vulnerability remediation MTTR and risk reduction.",
    enums={
        "speed": EnumDef(
            "RemediationSpeed",
            {
                "IMMEDIATE": "immediate",
                "FAST": "fast",
                "NORMAL": "normal",
                "SLOW": "slow",
                "OVERDUE": "overdue",
            },
        ),
        "compliance": EnumDef(
            "PatchCompliance",
            {
                "FULLY_COMPLIANT": "fully_compliant",
                "MOSTLY_COMPLIANT": "mostly_compliant",
                "PARTIALLY_COMPLIANT": "partially_compliant",
                "NON_COMPLIANT": "non_compliant",
                "EXEMPT": "exempt",
            },
        ),
        "risk_reduction": EnumDef(
            "RiskReduction",
            {
                "CRITICAL_ELIMINATED": "critical_eliminated",
                "SIGNIFICANT": "significant",
                "MODERATE": "moderate",
                "MINIMAL": "minimal",
                "NONE": "none",
            },
        ),
    },
    record_fields=[
        FieldDef("asset_id", str, ""),
        FieldDef("mttr_hours", float, 0.0),
        FieldDef("sla_target_hours", float, 72.0),
        FieldDef("sla_met", bool, False),
        FieldDef("risk_score_after", float, 0.0),
    ],
    score_field="risk_score_before",
    key_field="cve_id",
)

# Backward-compatible re-exports
RemediationSpeed = VulnRemediationAnalytics.RemediationSpeed
PatchCompliance = VulnRemediationAnalytics.PatchCompliance
RiskReduction = VulnRemediationAnalytics.RiskReduction
RemediationRecord = VulnRemediationAnalytics.Record
RemediationAnalysis = VulnRemediationAnalytics.Analysis
RemediationReport = VulnRemediationAnalytics.Report
