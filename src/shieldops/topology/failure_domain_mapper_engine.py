"""FailureDomainMapperEngine — failure domain mapper engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

FailureDomainMapperEngine = engine(
    "FailureDomainMapperEngine",
    module="operations",  # uses record_item
    description="Failure Domain Mapper Engine.",
    enums={
        "domain_type": EnumDef(
            "DomainType",
            {
                "AVAILABILITY_ZONE": "availability_zone",
                "REGION": "region",
                "RACK": "rack",
                "NETWORK_SEGMENT": "network_segment",
                "DATA_CENTER": "data_center",
            },
        ),
        "impact_severity": EnumDef(
            "ImpactSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "MINIMAL": "minimal",
            },
        ),
        "mapping_status": EnumDef(
            "MappingStatus",
            {
                "MAPPED": "mapped",
                "PARTIAL": "partial",
                "UNMAPPED": "unmapped",
                "STALE": "stale",
                "VERIFIED": "verified",
            },
        ),
    },
)

# Backward-compatible re-exports
DomainType = FailureDomainMapperEngine.DomainType
ImpactSeverity = FailureDomainMapperEngine.ImpactSeverity
MappingStatus = FailureDomainMapperEngine.MappingStatus
FailureDomainRecord = FailureDomainMapperEngine.Record
FailureDomainAnalysis = FailureDomainMapperEngine.Analysis
FailureDomainReport = FailureDomainMapperEngine.Report
