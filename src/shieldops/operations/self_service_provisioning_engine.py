"""SelfServiceProvisioningEngine Self-service infrastructure provisioning, request tracking, a..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SelfServiceProvisioningEngine = engine(
    "SelfServiceProvisioningEngine",
    module="operations",  # uses record_item
    description="Self-service provisioning with request tracking and approval automation.",
    enums={
        "provisioning_type": EnumDef(
            "ProvisioningType",
            {
                "COMPUTE": "compute",
                "DATABASE": "database",
                "STORAGE": "storage",
                "NETWORK": "network",
                "KUBERNETES": "kubernetes",
            },
        ),
        "provisioning_status": EnumDef(
            "ProvisioningStatus",
            {
                "PENDING": "pending",
                "APPROVED": "approved",
                "PROVISIONING": "provisioning",
                "COMPLETED": "completed",
                "FAILED": "failed",
            },
        ),
        "approval_mode": EnumDef(
            "ApprovalMode",
            {
                "AUTO_APPROVED": "auto_approved",
                "MANUAL_REVIEW": "manual_review",
                "POLICY_GATED": "policy_gated",
                "ESCALATED": "escalated",
                "DENIED": "denied",
            },
        ),
    },
)

# Backward-compatible re-exports
ProvisioningType = SelfServiceProvisioningEngine.ProvisioningType
ProvisioningStatus = SelfServiceProvisioningEngine.ProvisioningStatus
ApprovalMode = SelfServiceProvisioningEngine.ApprovalMode
SelfServiceProvisioningRecord = SelfServiceProvisioningEngine.Record
SelfServiceProvisioningAnalysis = SelfServiceProvisioningEngine.Analysis
SelfServiceProvisioningReport = SelfServiceProvisioningEngine.Report
