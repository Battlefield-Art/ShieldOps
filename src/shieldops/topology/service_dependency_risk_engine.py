"""Service Dependency Risk Engine. Quantify dependency risk, detect shared failure domains, an..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ServiceDependencyRiskEngine = engine(
    "ServiceDependencyRiskEngine",
    module="operations",  # uses record_item
    description="Quantify dependency risk, detect shared failure domains, recommend decoupli...",
    enums={
        "risk_level": EnumDef(
            "RiskLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "coupling_strength": EnumDef(
            "CouplingStrength",
            {
                "TIGHT": "tight",
                "MODERATE": "moderate",
                "LOOSE": "loose",
                "NONE": "none",
            },
        ),
        "failure_domain": EnumDef(
            "FailureDomain",
            {
                "AVAILABILITY_ZONE": "availability_zone",
                "REGION": "region",
                "PROVIDER": "provider",
                "SHARED_SERVICE": "shared_service",
            },
        ),
    },
    record_fields=[
        FieldDef("target_service", str, ""),
        FieldDef("call_frequency", float, 0.0),
        FieldDef("fallback_available", bool, False),
    ],
    score_field="risk_score",
    key_field="source_service",
)

# Backward-compatible re-exports
RiskLevel = ServiceDependencyRiskEngine.RiskLevel
CouplingStrength = ServiceDependencyRiskEngine.CouplingStrength
FailureDomain = ServiceDependencyRiskEngine.FailureDomain
DependencyRiskRecord = ServiceDependencyRiskEngine.Record
DependencyRiskAnalysis = ServiceDependencyRiskEngine.Analysis
DependencyRiskReport = ServiceDependencyRiskEngine.Report
