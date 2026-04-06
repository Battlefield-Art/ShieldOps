"""Audit Report Generator Engine — track and analyze compliance audit report generation."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AuditReportGeneratorEngine = engine(
    "AuditReportGeneratorEngine",
    description="Track and analyze compliance audit report generation.",
    enums={
        "report_type": EnumDef(
            "ReportType",
            {
                "SOC2_TYPE2": "soc2_type2",
                "PCI_ROC": "pci_roc",
                "HIPAA_ASSESSMENT": "hipaa_assessment",
                "FEDRAMP_PACKAGE": "fedramp_package",
                "GDPR_DPIA": "gdpr_dpia",
            },
        ),
        "report_status": EnumDef(
            "ReportStatus",
            {
                "DRAFT": "draft",
                "REVIEW": "review",
                "APPROVED": "approved",
                "DELIVERED": "delivered",
                "ARCHIVED": "archived",
            },
        ),
        "audit_outcome": EnumDef(
            "AuditOutcome",
            {
                "CLEAN": "clean",
                "QUALIFIED": "qualified",
                "ADVERSE": "adverse",
                "DISCLAIMER": "disclaimer",
            },
        ),
    },
    record_fields=[
        FieldDef("total_controls", int, 0),
        FieldDef("compliant_controls", int, 0),
        FieldDef("generation_time_ms", float, 0.0),
    ],
    score_field="compliance_score",
    key_field="report_name",
)

# Backward-compatible re-exports
ReportType = AuditReportGeneratorEngine.ReportType
ReportStatus = AuditReportGeneratorEngine.ReportStatus
AuditOutcome = AuditReportGeneratorEngine.AuditOutcome
AuditReportRecord = AuditReportGeneratorEngine.Record
AuditReportAnalysis = AuditReportGeneratorEngine.Analysis
AuditReportReport = AuditReportGeneratorEngine.Report
