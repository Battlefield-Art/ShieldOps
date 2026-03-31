"""State models for the Digital Forensics Lab Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class DFLStage(StrEnum):
    """Stages in the digital forensics lifecycle."""

    ACQUIRE_EVIDENCE = "acquire_evidence"
    ANALYZE_ARTIFACTS = "analyze_artifacts"
    EXTRACT_IOCS = "extract_iocs"
    BUILD_TIMELINE = "build_timeline"
    GENERATE_REPORT = "generate_report"
    REPORT = "report"


class EvidenceType(StrEnum):
    """Types of digital evidence."""

    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    NETWORK_CAPTURE = "network_capture"
    LOG_FILE = "log_file"
    REGISTRY_HIVE = "registry_hive"
    FILE_ARTIFACT = "file_artifact"


class ArtifactCategory(StrEnum):
    """Categories of forensic artifacts."""

    FILESYSTEM = "filesystem"
    REGISTRY = "registry"
    MEMORY = "memory"
    NETWORK = "network"
    BROWSER = "browser"
    APPLICATION = "application"


# --- Domain models ---


class EvidenceItem(BaseModel):
    """A piece of digital evidence acquired for analysis."""

    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.DISK_IMAGE
    source_host: str = ""
    file_path: str = ""
    hash_sha256: str = ""
    size_bytes: int = 0
    acquired_at: datetime | None = None
    chain_of_custody: list[str] = Field(default_factory=list)


class ForensicArtifact(BaseModel):
    """An artifact extracted from digital evidence."""

    artifact_id: str = ""
    evidence_id: str = ""
    category: ArtifactCategory = ArtifactCategory.FILESYSTEM
    name: str = ""
    value: str = ""
    timestamp: datetime | None = None
    significance: str = "low"
    notes: str = ""


class IOCEntry(BaseModel):
    """An indicator of compromise extracted from evidence."""

    ioc_id: str = ""
    ioc_type: str = ""
    value: str = ""
    confidence: float = 0.0
    source_artifact: str = ""
    mitre_technique: str = ""
    description: str = ""
    first_seen: datetime | None = None


class TimelineEvent(BaseModel):
    """An event in the forensic investigation timeline."""

    event_id: str = ""
    timestamp: datetime | None = None
    source: str = ""
    event_type: str = ""
    description: str = ""
    artifact_refs: list[str] = Field(default_factory=list)
    significance: str = "low"


class CustodyRecord(BaseModel):
    """Chain of custody record for evidence integrity."""

    record_id: str = ""
    evidence_id: str = ""
    action: str = ""
    handler: str = ""
    timestamp: datetime | None = None
    hash_verified: bool = False
    notes: str = ""


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestrator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class DigitalForensicsLabState(BaseModel):
    """Full state for a digital forensics lab run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: DFLStage = DFLStage.ACQUIRE_EVIDENCE

    # Inputs
    case_id: str = ""
    incident_id: str = ""
    target_hosts: list[str] = Field(default_factory=list)
    evidence_types: list[str] = Field(default_factory=list)

    # Pipeline fields
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    forensic_report: dict[str, Any] = Field(default_factory=dict)
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_evidence: int = 0
    total_artifacts: int = 0
    total_iocs: int = 0
    timeline_events: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
