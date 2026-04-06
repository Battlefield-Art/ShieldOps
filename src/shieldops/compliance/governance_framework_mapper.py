"""Governance Framework Mapper — map controls to governance frameworks."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

GovernanceFrameworkMapper = engine(
    "GovernanceFrameworkMapper",
    description="Map controls to governance frameworks, track maturity, identify mapping gaps.",
    enums={
        "framework": EnumDef(
            "Framework",
            {
                "NIST_CSF": "nist_csf",
                "ISO_27001": "iso_27001",
                "SOC2": "soc2",
                "HIPAA": "hipaa",
                "PCI_DSS": "pci_dss",
            },
        ),
        "mapping_status": EnumDef(
            "MappingStatus",
            {
                "MAPPED": "mapped",
                "PARTIAL": "partial",
                "UNMAPPED": "unmapped",
                "NOT_APPLICABLE": "not_applicable",
                "IN_PROGRESS": "in_progress",
            },
        ),
        "control_maturity": EnumDef(
            "ControlMaturity",
            {
                "OPTIMIZED": "optimized",
                "MANAGED": "managed",
                "DEFINED": "defined",
                "REPEATABLE": "repeatable",
                "INITIAL": "initial",
            },
        ),
    },
    score_field="mapping_score",
    key_field="control_name",
)

# Backward-compatible re-exports
Framework = GovernanceFrameworkMapper.Framework
MappingStatus = GovernanceFrameworkMapper.MappingStatus
ControlMaturity = GovernanceFrameworkMapper.ControlMaturity
FrameworkRecord = GovernanceFrameworkMapper.Record
FrameworkAnalysis = GovernanceFrameworkMapper.Analysis
FrameworkMappingReport = GovernanceFrameworkMapper.Report
