"""State models for Evidence Collector Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EvidenceStage(StrEnum):
    """Stages in the evidence collection workflow."""

    IDENTIFY_SOURCES = "identify_sources"
    COLLECT_ARTIFACTS = "collect_artifacts"
    HASH_VERIFY = "hash_verify"
    CHAIN_OF_CUSTODY = "chain_of_custody"
    PACKAGE_EVIDENCE = "package_evidence"
    REPORT = "report"


class ArtifactType(StrEnum):
    """Types of forensic artifacts."""

    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image"
    LOG_FILE = "log_file"
    NETWORK_CAPTURE = "network_capture"
    REGISTRY_HIVE = "registry_hive"
    PROCESS_LIST = "process_list"


class CustodyStatus(StrEnum):
    """Chain of custody status."""

    COLLECTED = "collected"
    VERIFIED = "verified"
    TRANSFERRED = "transferred"
    STORED = "stored"
    COMPROMISED = "compromised"


class Artifact(BaseModel):
    """A collected forensic artifact."""

    id: str = ""
    artifact_type: ArtifactType = ArtifactType.LOG_FILE
    source: str = ""
    hash_sha256: str = ""
    size_bytes: int = 0
    custody: CustodyStatus = CustodyStatus.COLLECTED


class EvidenceType(StrEnum):
    """Evidence source types for collection."""

    MEMORY_DUMP = "memory_dump"
    LOG_FILES = "log_files"
    NETWORK_CAPTURE = "network_capture"
    CONFIG_SNAPSHOT = "config_snapshot"
    DISK_IMAGE = "disk_image"
    PROCESS_LIST = "process_list"
    REGISTRY_HIVE = "registry_hive"


class IntegrityStatus(StrEnum):
    """Integrity verification status."""

    VERIFIED = "verified"
    TAMPERED = "tampered"
    UNKNOWN = "unknown"


class EvidenceSource(BaseModel):
    """An identified evidence source."""

    id: str = ""
    host: str = ""
    source_type: EvidenceType = EvidenceType.LOG_FILES
    path: str = ""
    accessible: bool = True
    priority: str = "medium"
    estimated_size_mb: int = 0


class CollectedArtifact(BaseModel):
    """A collected forensic artifact with metadata."""

    id: str = ""
    source_id: str = ""
    evidence_type: EvidenceType = EvidenceType.LOG_FILES
    file_path: str = ""
    size_bytes: int = 0
    sha256_hash: str = ""
    collected_at: float = 0.0
    collector: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrityVerification(BaseModel):
    """Result of an integrity verification check."""

    id: str = ""
    artifact_id: str = ""
    status: IntegrityStatus = IntegrityStatus.UNKNOWN
    hash_verified: bool = False
    original_hash: str = ""
    current_hash: str = ""
    checked_at: float = 0.0
    notes: str = ""


class ChainOfCustody(BaseModel):
    """A chain-of-custody record entry."""

    id: str = ""
    artifact_id: str = ""
    custodian: str = ""
    action: str = ""
    timestamp: float = 0.0
    location: str = ""
    purpose: str = ""
    signature: str = ""


class EvidencePackage(BaseModel):
    """A sealed evidence package for handoff."""

    id: str = ""
    incident_id: str = ""
    artifact_ids: list[str] = Field(default_factory=list)
    package_hash: str = ""
    created_at: float = 0.0
    storage_location: str = ""
    encryption_key_id: str = ""
    total_size_bytes: int = 0


class EvidenceCollectorState(BaseModel):
    """Full state for Evidence Collector."""

    request_id: str = ""
    stage: EvidenceStage = EvidenceStage.IDENTIFY_SOURCES
    tenant_id: str = ""
    incident_id: str = ""
    incident_details: dict[str, Any] = Field(default_factory=dict)
    sources: list[EvidenceSource] = Field(default_factory=list)
    artifacts: list[CollectedArtifact] = Field(default_factory=list)
    verifications: list[IntegrityVerification] = Field(default_factory=list)
    custody_records: list[ChainOfCustody] = Field(default_factory=list)
    package: dict[str, Any] = Field(default_factory=dict)
    report: dict[str, Any] = Field(default_factory=dict)
    verified_count: int = 0
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_start: float = 0.0
