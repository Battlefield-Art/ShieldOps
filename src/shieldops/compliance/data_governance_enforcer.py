"""Data Governance Enforcer — enforce data classification and governance policies."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DataGovernanceEnforcer = engine(
    "DataGovernanceEnforcer",
    description="Enforce data governance policies, track classification, identify governance...",
    enums={
        "data_classification": EnumDef(
            "DataClassification",
            {
                "PUBLIC": "public",
                "INTERNAL": "internal",
                "CONFIDENTIAL": "confidential",
                "RESTRICTED": "restricted",
                "TOP_SECRET": "top_secret",
            },
        ),
        "governance_action": EnumDef(
            "GovernanceAction",
            {
                "CLASSIFY": "classify",
                "ENCRYPT": "encrypt",
                "MASK": "mask",
                "RETAIN": "retain",
                "DELETE": "delete",
            },
        ),
        "governance_status": EnumDef(
            "GovernanceStatus",
            {
                "COMPLIANT": "compliant",
                "NON_COMPLIANT": "non_compliant",
                "REMEDIATION": "remediation",
                "EXCEPTION": "exception",
                "UNKNOWN": "unknown",
            },
        ),
    },
    score_field="governance_score",
    key_field="data_asset",
)

# Backward-compatible re-exports
DataClassification = DataGovernanceEnforcer.DataClassification
GovernanceAction = DataGovernanceEnforcer.GovernanceAction
GovernanceStatus = DataGovernanceEnforcer.GovernanceStatus
GovernanceRecord = DataGovernanceEnforcer.Record
GovernanceAnalysis = DataGovernanceEnforcer.Analysis
DataGovernanceReport = DataGovernanceEnforcer.Report
