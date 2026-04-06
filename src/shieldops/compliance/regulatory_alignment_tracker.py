"""Regulatory Alignment Tracker — track alignment with regulatory requirements."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

RegulatoryAlignmentTracker = engine(
    "RegulatoryAlignmentTracker",
    description="Track regulatory alignment, identify compliance gaps, score alignment matur...",
    enums={
        "regulation": EnumDef(
            "Regulation",
            {
                "GDPR": "gdpr",
                "CCPA": "ccpa",
                "SOX": "sox",
                "HIPAA": "hipaa",
                "PCI_DSS": "pci_dss",
            },
        ),
        "alignment_status": EnumDef(
            "AlignmentStatus",
            {
                "ALIGNED": "aligned",
                "PARTIALLY_ALIGNED": "partially_aligned",
                "NON_ALIGNED": "non_aligned",
                "IN_PROGRESS": "in_progress",
                "NOT_APPLICABLE": "not_applicable",
            },
        ),
        "compliance_risk": EnumDef(
            "ComplianceRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MINIMAL": "minimal",
            },
        ),
    },
    score_field="alignment_score",
    key_field="requirement_name",
)

# Backward-compatible re-exports
Regulation = RegulatoryAlignmentTracker.Regulation
AlignmentStatus = RegulatoryAlignmentTracker.AlignmentStatus
ComplianceRisk = RegulatoryAlignmentTracker.ComplianceRisk
AlignmentRecord = RegulatoryAlignmentTracker.Record
AlignmentAnalysis = RegulatoryAlignmentTracker.Analysis
RegulatoryAlignmentReport = RegulatoryAlignmentTracker.Report
