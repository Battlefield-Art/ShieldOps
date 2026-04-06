"""OffensiveSecurityMetrics — Offensive security KPIs."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OffensiveSecurityMetrics = engine(
    "OffensiveSecurityMetrics",
    description="Track offensive security KPIs and posture.",
    enums={
        "surface": EnumDef(
            "AttackSurface",
            {
                "EXTERNAL": "external",
                "INTERNAL": "internal",
                "CLOUD": "cloud",
                "API": "api",
                "SUPPLY_CHAIN": "supply_chain",
                "SOCIAL": "social",
            },
        ),
        "density": EnumDef(
            "FindingDensity",
            {
                "VERY_HIGH": "very_high",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "MINIMAL": "minimal",
            },
        ),
        "speed": EnumDef(
            "RemediationSpeed",
            {
                "WITHIN_SLA": "within_sla",
                "NEAR_SLA": "near_sla",
                "EXCEEDED_SLA": "exceeded_sla",
                "UNRESOLVED": "unresolved",
            },
        ),
    },
    record_fields=[
        FieldDef("findings_count", int, 0),
        FieldDef("remediation_days", float, 0.0),
    ],
)

# Backward-compatible re-exports
AttackSurface = OffensiveSecurityMetrics.AttackSurface
FindingDensity = OffensiveSecurityMetrics.FindingDensity
RemediationSpeed = OffensiveSecurityMetrics.RemediationSpeed
OffensiveMetricRecord = OffensiveSecurityMetrics.Record
OffensiveMetricAnalysis = OffensiveSecurityMetrics.Analysis
OffensiveMetricReport = OffensiveSecurityMetrics.Report
