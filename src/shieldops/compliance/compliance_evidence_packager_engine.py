"""Compliance Evidence Packager Engine — track evidence collection and packaging for audits."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ComplianceEvidencePackagerEngine = engine(
    "ComplianceEvidencePackagerEngine",
    description="Track evidence collection and packaging for compliance audits.",
    enums={
        "evidence_type": EnumDef(
            "EvidenceType",
            {
                "LOG_EXPORT": "log_export",
                "CONFIG_SNAPSHOT": "config_snapshot",
                "POLICY_DOCUMENT": "policy_document",
                "SCAN_RESULT": "scan_result",
                "ACCESS_REVIEW": "access_review",
            },
        ),
        "compliance_framework": EnumDef(
            "ComplianceFramework",
            {
                "SOC2": "soc2",
                "PCI_DSS": "pci_dss",
                "HIPAA": "hipaa",
                "FEDRAMP": "fedramp",
                "GDPR": "gdpr",
                "ISO_27001": "iso_27001",
            },
        ),
        "packaging_status": EnumDef(
            "PackagingStatus",
            {
                "COMPLETE": "complete",
                "PARTIAL": "partial",
                "MISSING": "missing",
                "EXPIRED": "expired",
                "PENDING": "pending",
            },
        ),
    },
    record_fields=[
        FieldDef("artifact_count", int, 0),
        FieldDef("hash_verified", bool, False),
    ],
    score_field="completeness_score",
    key_field="control_id",
)

# Backward-compatible re-exports
EvidenceType = ComplianceEvidencePackagerEngine.EvidenceType
ComplianceFramework = ComplianceEvidencePackagerEngine.ComplianceFramework
PackagingStatus = ComplianceEvidencePackagerEngine.PackagingStatus
EvidenceRecord = ComplianceEvidencePackagerEngine.Record
EvidenceAnalysis = ComplianceEvidencePackagerEngine.Analysis
EvidenceReport = ComplianceEvidencePackagerEngine.Report
