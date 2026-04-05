"""State models for the Forensic Evidence Chain Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class FECStage(StrEnum):
    """Workflow stages for forensic evidence chain."""

    COLLECT_EVIDENCE = "collect_evidence"
    HASH_ARTIFACTS = "hash_artifacts"
    CHAIN_CUSTODY = "chain_custody"
    VALIDATE_INTEGRITY = "validate_integrity"
    PACKAGE_FOR_LEGAL = "package_for_legal"
    REPORT = "report"


class EvidenceType(StrEnum):
    """Type of forensic evidence."""

    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    NETWORK_CAPTURE = "network_capture"
    LOG_FILE = "log_file"
    REGISTRY_HIVE = "registry_hive"


class CustodyStatus(StrEnum):
    """Status of chain-of-custody."""

    INTACT = "intact"
    TRANSFERRED = "transferred"
    SEALED = "sealed"
    COMPROMISED = "compromised"
    ARCHIVED = "archived"


# ── Domain Models ─────────────────────────────────────


class EvidenceItem(BaseModel):
    """A collected forensic evidence item."""

    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.LOG_FILE
    source: str = ""
    size_bytes: int = 0
    collected_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ArtifactHash(BaseModel):
    """Cryptographic hash of an evidence artifact."""

    evidence_id: str = ""
    algorithm: str = "sha256"
    hash_value: str = ""
    verified: bool = False


class CustodyRecord(BaseModel):
    """Chain-of-custody transfer record."""

    record_id: str = ""
    evidence_id: str = ""
    from_custodian: str = ""
    to_custodian: str = ""
    status: CustodyStatus = CustodyStatus.INTACT
    timestamp: str = ""


class IntegrityResult(BaseModel):
    """Result of integrity validation."""

    evidence_id: str = ""
    hash_match: bool = True
    tamper_detected: bool = False
    details: str = ""


class LegalPackage(BaseModel):
    """Evidence packaged for legal proceedings."""

    package_id: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    custody_chain_valid: bool = True
    format: str = "forensic_standard"
    notes: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the forensic evidence chain workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ForensicEvidenceChainState(BaseModel):
    """Full state for the Forensic Evidence Chain workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: FECStage = FECStage.COLLECT_EVIDENCE
    config: dict[str, Any] = Field(default_factory=dict)

    evidence_items: list[dict[str, Any]] = Field(default_factory=list)
    artifact_hashes: list[dict[str, Any]] = Field(default_factory=list)
    custody_records: list[dict[str, Any]] = Field(default_factory=list)
    integrity_results: list[dict[str, Any]] = Field(default_factory=list)
    legal_packages: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
