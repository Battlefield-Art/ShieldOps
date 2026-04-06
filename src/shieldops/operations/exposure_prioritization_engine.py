"""ExposurePrioritizationEngine — Prioritize exposures by CVSS, EPSS, and business context."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ExposurePrioritizationEngine = engine(
    "ExposurePrioritizationEngine",
    description="Prioritize exposures by CVSS, EPSS, and business context.",
    enums={
        "priority_factor": EnumDef(
            "PriorityFactor",
            {
                "CVSS": "cvss",
                "EPSS": "epss",
                "BUSINESS_CONTEXT": "business_context",
                "EXPLOIT_MATURITY": "exploit_maturity",
            },
        ),
        "business_criticality": EnumDef(
            "BusinessCriticality",
            {
                "MISSION_CRITICAL": "mission_critical",
                "BUSINESS_CRITICAL": "business_critical",
                "OPERATIONAL": "operational",
                "NON_CRITICAL": "non_critical",
            },
        ),
        "remediation_effort": EnumDef(
            "RemediationEffort",
            {
                "TRIVIAL": "trivial",
                "LOW": "low",
                "MEDIUM": "medium",
                "HIGH": "high",
                "COMPLEX": "complex",
            },
        ),
    },
    record_fields=[
        FieldDef("cvss_score", float, 0.0),
        FieldDef("epss_score", float, 0.0),
    ],
)

# Backward-compatible re-exports
PriorityFactor = ExposurePrioritizationEngine.PriorityFactor
BusinessCriticality = ExposurePrioritizationEngine.BusinessCriticality
RemediationEffort = ExposurePrioritizationEngine.RemediationEffort
PrioritizationRecord = ExposurePrioritizationEngine.Record
PrioritizationAnalysis = ExposurePrioritizationEngine.Analysis
PrioritizationReport = ExposurePrioritizationEngine.Report
