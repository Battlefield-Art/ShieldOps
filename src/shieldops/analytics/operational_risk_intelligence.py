"""OperationalRiskIntelligence Operational risk scoring, risk trend analysis, mitigation track..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OperationalRiskIntelligence = engine(
    "OperationalRiskIntelligence",
    module="operations",  # uses record_item
    description="Operational risk scoring with trend analysis, mitigation tracking, and heat...",
    enums={
        "risk_domain": EnumDef(
            "RiskDomain",
            {
                "AVAILABILITY": "availability",
                "SECURITY": "security",
                "COMPLIANCE": "compliance",
                "PERFORMANCE": "performance",
                "COST": "cost",
                "OPERATIONAL": "operational",
            },
        ),
        "risk_severity": EnumDef(
            "RiskSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "ACCEPTED": "accepted",
            },
        ),
        "mitigation_status": EnumDef(
            "MitigationStatus",
            {
                "NOT_STARTED": "not_started",
                "IN_PROGRESS": "in_progress",
                "MITIGATED": "mitigated",
                "ACCEPTED": "accepted",
                "TRANSFERRED": "transferred",
            },
        ),
    },
    record_fields=[
        FieldDef("likelihood_pct", float, 0.0),
        FieldDef("impact_score", float, 0.0),
        FieldDef("residual_risk", float, 0.0),
        FieldDef("mitigation_effectiveness_pct", float, 0.0),
        FieldDef("days_open", int, 0),
    ],
    score_field="risk_score",
)

# Backward-compatible re-exports
RiskDomain = OperationalRiskIntelligence.RiskDomain
RiskSeverity = OperationalRiskIntelligence.RiskSeverity
MitigationStatus = OperationalRiskIntelligence.MitigationStatus
OperationalRiskRecord = OperationalRiskIntelligence.Record
OperationalRiskAnalysis = OperationalRiskIntelligence.Analysis
OperationalRiskReport = OperationalRiskIntelligence.Report
