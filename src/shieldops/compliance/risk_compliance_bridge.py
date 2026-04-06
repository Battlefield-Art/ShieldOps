"""Risk Compliance Bridge map risk findings to compliance controls, compute compliance risk sc..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RiskComplianceBridge = engine(
    "RiskComplianceBridge",
    description="Map risks to controls, compute compliance risk scores, detect unmapped risks.",
    enums={
        "framework": EnumDef(
            "ComplianceFramework",
            {
                "NIST": "nist",
                "CIS": "cis",
                "ISO27001": "iso27001",
                "SOC2": "soc2",
            },
        ),
        "mapping": EnumDef(
            "RiskToControlMapping",
            {
                "DIRECT": "direct",
                "INDIRECT": "indirect",
                "PARTIAL": "partial",
                "UNMAPPED": "unmapped",
            },
        ),
        "impact": EnumDef(
            "ComplianceImpact",
            {
                "VIOLATION": "violation",
                "WARNING": "warning",
                "OBSERVATION": "observation",
                "COMPLIANT": "compliant",
            },
        ),
    },
    record_fields=[
        FieldDef("control_id", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="risk_score",
    key_field="risk_id",
)

# Backward-compatible re-exports
ComplianceFramework = RiskComplianceBridge.ComplianceFramework
RiskToControlMapping = RiskComplianceBridge.RiskToControlMapping
ComplianceImpact = RiskComplianceBridge.ComplianceImpact
RiskComplianceRecord = RiskComplianceBridge.Record
RiskComplianceAnalysis = RiskComplianceBridge.Analysis
RiskComplianceReport = RiskComplianceBridge.Report
