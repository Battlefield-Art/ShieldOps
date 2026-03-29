"""Endpoint Forensics Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ForensicsStage(StrEnum):
    COLLECT_ARTIFACTS = "collect_artifacts"
    ANALYZE_MEMORY = "analyze_memory"
    INVESTIGATE_PROCESSES = "investigate_processes"
    CARVE_FILES = "carve_files"
    RECONSTRUCT_TIMELINE = "reconstruct_timeline"
    REPORT = "report"


class ArtifactType(StrEnum):
    MEMORY_DUMP = "memory_dump"
    PROCESS_LIST = "process_list"
    NETWORK_CONNECTIONS = "network_connections"
    FILE_SYSTEM = "file_system"
    REGISTRY = "registry"
    EVENT_LOG = "event_log"
    PREFETCH = "prefetch"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ForensicArtifact(BaseModel):
    """A forensic artifact collected from an endpoint."""

    id: str = ""
    artifact_type: ArtifactType = ArtifactType.FILE_SYSTEM
    source: str = ""
    size_bytes: int = 0
    hash_sha256: str = ""
    collected_at: datetime | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class MemoryFinding(BaseModel):
    """A finding from memory analysis."""

    id: str = ""
    finding_type: str = ""
    process_name: str = ""
    pid: int = 0
    severity: FindingSeverity = FindingSeverity.INFO
    details: str = ""
    indicators: list[str] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    """A reconstructed timeline event."""

    timestamp: datetime | None = None
    source: str = ""
    event_type: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    evidence: dict[str, Any] = Field(default_factory=dict)


class EndpointForensicsState(BaseModel):
    """Main state for the Endpoint Forensics agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    endpoint_id: str = ""
    case_id: str = ""
    stage: ForensicsStage = ForensicsStage.COLLECT_ARTIFACTS

    # Artifacts
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    total_artifacts: int = 0

    # Memory analysis
    memory_findings: list[dict[str, Any]] = Field(default_factory=list)
    injected_processes: int = 0

    # Process investigation
    suspicious_processes: list[dict[str, Any]] = Field(default_factory=list)
    process_tree: list[dict[str, Any]] = Field(default_factory=list)

    # File carving
    carved_files: list[dict[str, Any]] = Field(default_factory=list)
    malware_found: int = 0

    # Timeline
    timeline: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    ioc_list: list[str] = Field(default_factory=list)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
