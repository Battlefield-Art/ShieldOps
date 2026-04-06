"""Showback Chargeback Automator compute allocation models, detect allocation drift, generate..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ShowbackChargebackAutomator = engine(
    "ShowbackChargebackAutomator",
    description="Compute allocation models, detect drift, generate chargeback invoices.",
    enums={
        "allocation_method": EnumDef(
            "AllocationMethod",
            {
                "TAG_BASED": "tag_based",
                "PROPORTIONAL": "proportional",
                "USAGE_WEIGHTED": "usage_weighted",
                "FIXED": "fixed",
            },
        ),
        "invoice_status": EnumDef(
            "InvoiceStatus",
            {
                "DRAFT": "draft",
                "PENDING": "pending",
                "APPROVED": "approved",
                "SENT": "sent",
            },
        ),
        "drift_severity": EnumDef(
            "DriftSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("allocated_cost", float, 0.0),
        FieldDef("actual_cost", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="team_id",
)

# Backward-compatible re-exports
AllocationMethod = ShowbackChargebackAutomator.AllocationMethod
InvoiceStatus = ShowbackChargebackAutomator.InvoiceStatus
DriftSeverity = ShowbackChargebackAutomator.DriftSeverity
ChargebackRecord = ShowbackChargebackAutomator.Record
ChargebackAnalysis = ShowbackChargebackAutomator.Analysis
ChargebackReport = ShowbackChargebackAutomator.Report
