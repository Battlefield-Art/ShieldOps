"""Cross Framework Control Mapper compute control overlap matrix, detect unmapped controls, ra..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CrossFrameworkControlMapper = engine(
    "CrossFrameworkControlMapper",
    description="Compute control overlap matrix, detect unmapped controls, rank frameworks b...",
    enums={
        "framework": EnumDef(
            "Framework",
            {
                "SOC2": "soc2",
                "ISO27001": "iso27001",
                "NIST": "nist",
                "PCI_DSS": "pci_dss",
            },
        ),
        "mapping_confidence": EnumDef(
            "MappingConfidence",
            {
                "EXACT": "exact",
                "STRONG": "strong",
                "PARTIAL": "partial",
                "WEAK": "weak",
            },
        ),
        "control_domain": EnumDef(
            "ControlDomain",
            {
                "ACCESS": "access",
                "ENCRYPTION": "encryption",
                "MONITORING": "monitoring",
                "INCIDENT_RESPONSE": "incident_response",
            },
        ),
    },
    record_fields=[
        FieldDef("mapped_to_framework", str, ""),
        FieldDef("mapped_to_control", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="coverage_score",
    key_field="control_id",
)

# Backward-compatible re-exports
Framework = CrossFrameworkControlMapper.Framework
MappingConfidence = CrossFrameworkControlMapper.MappingConfidence
ControlDomain = CrossFrameworkControlMapper.ControlDomain
ControlMappingRecord = CrossFrameworkControlMapper.Record
ControlMappingAnalysis = CrossFrameworkControlMapper.Analysis
ControlMappingReport = CrossFrameworkControlMapper.Report
