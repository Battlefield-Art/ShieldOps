"""Regulatory Mapping Engine — map data findings to regulatory requirements."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RegulatoryMappingEngine = engine(
    "RegulatoryMappingEngine",
    description="Map data findings to regulatory requirements and track compliance.",
    enums={
        "mapping_status": EnumDef(
            "MappingStatus",
            {
                "MAPPED": "mapped",
                "UNMAPPED": "unmapped",
                "PARTIAL": "partial",
                "EXEMPT": "exempt",
                "DISPUTED": "disputed",
            },
        ),
        "compliance_outcome": EnumDef(
            "ComplianceOutcome",
            {
                "COMPLIANT": "compliant",
                "NON_COMPLIANT": "non_compliant",
                "REMEDIATION_NEEDED": "remediation_needed",
                "PENDING_REVIEW": "pending_review",
                "EXEMPT": "exempt",
            },
        ),
        "regulation_scope": EnumDef(
            "RegulationScope",
            {
                "GLOBAL": "global",
                "US_FEDERAL": "us_federal",
                "US_STATE": "us_state",
                "EU": "eu",
                "INDUSTRY": "industry",
            },
        ),
    },
    record_fields=[
        FieldDef("regulation", str, ""),
        FieldDef("requirement", str, ""),
        FieldDef("gap_count", int, 0),
    ],
    key_field="finding_id",
)

# Backward-compatible re-exports
MappingStatus = RegulatoryMappingEngine.MappingStatus
ComplianceOutcome = RegulatoryMappingEngine.ComplianceOutcome
RegulationScope = RegulatoryMappingEngine.RegulationScope
RegulatoryMappingRecord = RegulatoryMappingEngine.Record
RegulatoryMappingAnalysis = RegulatoryMappingEngine.Analysis
RegulatoryMappingReport = RegulatoryMappingEngine.Report
