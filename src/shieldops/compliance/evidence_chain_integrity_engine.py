"""Evidence Chain Integrity Engine compute chain integrity score, detect broken evidence chain..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EvidenceChainIntegrityEngine = engine(
    "EvidenceChainIntegrityEngine",
    description="Compute chain integrity score, detect broken evidence chains, rank evidence...",
    enums={
        "integrity_status": EnumDef(
            "IntegrityStatus",
            {
                "VERIFIED": "verified",
                "SUSPECT": "suspect",
                "BROKEN": "broken",
                "UNKNOWN": "unknown",
            },
        ),
        "chain_type": EnumDef(
            "ChainType",
            {
                "COLLECTION": "collection",
                "REVIEW": "review",
                "APPROVAL": "approval",
                "ARCHIVAL": "archival",
            },
        ),
        "integrity_risk": EnumDef(
            "IntegrityRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("evidence_id", str, ""),
        FieldDef("chain_length", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="integrity_score",
    key_field="chain_id",
)

# Backward-compatible re-exports
IntegrityStatus = EvidenceChainIntegrityEngine.IntegrityStatus
ChainType = EvidenceChainIntegrityEngine.ChainType
IntegrityRisk = EvidenceChainIntegrityEngine.IntegrityRisk
EvidenceChainRecord = EvidenceChainIntegrityEngine.Record
EvidenceChainAnalysis = EvidenceChainIntegrityEngine.Analysis
EvidenceChainReport = EvidenceChainIntegrityEngine.Report
