"""ThreatComplianceMapper — threat compliance mapper."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ThreatComplianceMapper = engine(
    "ThreatComplianceMapper",
    module="operations",  # uses record_item
    description="Threat Compliance Mapper.",
    enums={
        "compliance_framework": EnumDef(
            "ComplianceFramework",
            {
                "NIST_CSF": "nist_csf",
                "ISO_27001": "iso_27001",
                "SOC2": "soc2",
                "PCI_DSS": "pci_dss",
                "HIPAA": "hipaa",
            },
        ),
        "mapping_status": EnumDef(
            "MappingStatus",
            {
                "MAPPED": "mapped",
                "PARTIAL": "partial",
                "UNMAPPED": "unmapped",
                "IN_REVIEW": "in_review",
                "DEPRECATED": "deprecated",
            },
        ),
        "control_effectiveness": EnumDef(
            "ControlEffectiveness",
            {
                "EFFECTIVE": "effective",
                "PARTIALLY_EFFECTIVE": "partially_effective",
                "INEFFECTIVE": "ineffective",
                "NOT_IMPLEMENTED": "not_implemented",
                "NOT_APPLICABLE": "not_applicable",
            },
        ),
    },
)

# Backward-compatible re-exports
ComplianceFramework = ThreatComplianceMapper.ComplianceFramework
MappingStatus = ThreatComplianceMapper.MappingStatus
ControlEffectiveness = ThreatComplianceMapper.ControlEffectiveness
ThreatComplianceMapperRecord = ThreatComplianceMapper.Record
ThreatComplianceMapperAnalysis = ThreatComplianceMapper.Analysis
ThreatComplianceMapperReport = ThreatComplianceMapper.Report
