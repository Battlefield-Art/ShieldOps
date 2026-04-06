"""Entitlement Risk Scorer Engine — score entitlement risk for access reviews."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EntitlementRiskScorerEngine = engine(
    "EntitlementRiskScorerEngine",
    description="Score entitlement risk for access reviews and identity governance.",
    enums={
        "risk_category": EnumDef(
            "RiskCategory",
            {
                "PRIVILEGE_CREEP": "privilege_creep",
                "SEPARATION_OF_DUTIES": "separation_of_duties",
                "STALE_ACCESS": "stale_access",
                "ORPHANED_ENTITLEMENT": "orphaned_entitlement",
                "EXCESSIVE_SCOPE": "excessive_scope",
            },
        ),
        "identity_type": EnumDef(
            "IdentityType",
            {
                "HUMAN": "human",
                "SERVICE_ACCOUNT": "service_account",
                "AI_AGENT": "ai_agent",
                "GROUP": "group",
                "ROLE": "role",
            },
        ),
        "risk_trend": EnumDef(
            "RiskTrend",
            {
                "INCREASING": "increasing",
                "STABLE": "stable",
                "DECREASING": "decreasing",
                "NEW": "new",
                "RESOLVED": "resolved",
            },
        ),
    },
    record_fields=[
        FieldDef("days_since_use", int, 0),
        FieldDef("permission_count", int, 0),
    ],
    score_field="risk_score",
    key_field="entitlement_id",
)

# Backward-compatible re-exports
RiskCategory = EntitlementRiskScorerEngine.RiskCategory
IdentityType = EntitlementRiskScorerEngine.IdentityType
RiskTrend = EntitlementRiskScorerEngine.RiskTrend
EntitlementRiskScorerRecord = EntitlementRiskScorerEngine.Record
EntitlementRiskScorerAnalysis = EntitlementRiskScorerEngine.Analysis
EntitlementRiskScorerReport = EntitlementRiskScorerEngine.Report
