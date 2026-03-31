"""State models for the Cloud Forensics Collector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class CFCStage(StrEnum):
    """Stages in the cloud forensics collection lifecycle."""

    IDENTIFY_SCOPE = "identify_scope"
    COLLECT_LOGS = "collect_logs"
    CAPTURE_SNAPSHOTS = "capture_snapshots"
    PRESERVE_EVIDENCE = "preserve_evidence"
    ANALYZE = "analyze"
    REPORT = "report"


class CloudProvider(StrEnum):
    """Supported cloud providers for forensics."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    MULTI_CLOUD = "multi_cloud"


class EvidenceType(StrEnum):
    """Types of forensic evidence collected."""

    CLOUD_TRAIL = "cloud_trail"
    AUDIT_LOG = "audit_log"
    ACTIVITY_LOG = "activity_log"
    DISK_SNAPSHOT = "disk_snapshot"
    MEMORY_DUMP = "memory_dump"
    NETWORK_FLOW = "network_flow"
    CONTAINER_LOG = "container_log"
    API_CALL_LOG = "api_call_log"


# --- Domain models ---


class ForensicScope(BaseModel):
    """Scope definition for a forensics investigation."""

    scope_id: str = ""
    incident_id: str = ""
    cloud_provider: CloudProvider = CloudProvider.AWS
    region: str = ""
    account_id: str = ""
    resource_ids: list[str] = Field(default_factory=list)
    time_start: datetime | None = None
    time_end: datetime | None = None
    investigator: str = ""


class CloudLogCollection(BaseModel):
    """Cloud audit log collection record."""

    collection_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    log_type: EvidenceType = EvidenceType.CLOUD_TRAIL
    records_collected: int = 0
    size_bytes: int = 0
    time_range: str = ""
    integrity_hash: str = ""
    collected_at: datetime | None = None


class DiskSnapshot(BaseModel):
    """Forensic disk snapshot record."""

    snapshot_id: str = ""
    resource_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    size_gb: float = 0.0
    encrypted: bool = True
    integrity_hash: str = ""
    captured_at: datetime | None = None


class EvidenceRecord(BaseModel):
    """Chain of custody evidence record."""

    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.CLOUD_TRAIL
    source: str = ""
    integrity_hash: str = ""
    chain_of_custody: list[str] = Field(
        default_factory=list,
    )
    preserved_at: datetime | None = None
    storage_location: str = ""
    tamper_proof: bool = True


class ForensicAnalysis(BaseModel):
    """Analysis result from forensic evidence."""

    analysis_id: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    indicators_of_compromise: list[str] = Field(
        default_factory=list,
    )
    severity: str = "medium"
    confidence: float = 0.0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the forensics workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudForensicsCollectorState(BaseModel):
    """Full state for a cloud forensics collector run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: CFCStage = CFCStage.IDENTIFY_SCOPE

    # Inputs
    case_name: str = ""
    incident_id: str = ""
    cloud_provider: CloudProvider = CloudProvider.AWS
    target_resources: list[str] = Field(
        default_factory=list,
    )
    time_range: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    forensic_scope: dict[str, Any] = Field(
        default_factory=dict,
    )
    collected_logs: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    snapshots: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    preserved_evidence: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    analysis: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_evidence: int = 0
    iocs_found: int = 0
    chain_of_custody_valid: bool = True
    severity: str = "medium"

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
