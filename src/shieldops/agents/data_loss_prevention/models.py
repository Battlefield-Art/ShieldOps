"""Data Loss Prevention Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DLPStage(StrEnum):
    DISCOVER_DATA_FLOWS = "discover_data_flows"
    CLASSIFY_SENSITIVE_DATA = "classify_sensitive_data"
    DETECT_EXFILTRATION = "detect_exfiltration"
    ENFORCE_POLICIES = "enforce_policies"
    RESPOND_TO_INCIDENTS = "respond_to_incidents"
    REPORT = "report"


class DataSensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"  # noqa: S105


class ExfiltrationChannel(StrEnum):
    ENDPOINT = "endpoint"
    CLOUD_STORAGE = "cloud_storage"
    EMAIL = "email"
    BROWSER = "browser"
    API = "api"
    AI_PIPELINE = "ai_pipeline"
    MCP_TOOL = "mcp_tool"


class DataFlow(BaseModel):
    """A tracked data movement between source and destination."""

    id: str = ""
    source: str = ""
    destination: str = ""
    channel: ExfiltrationChannel = ExfiltrationChannel.ENDPOINT
    protocol: str = ""
    volume_mb: float = 0.0
    records_count: int = 0
    user_identity: str = ""
    timestamp: float = 0.0
    is_encrypted: bool = False
    geo_source: str = ""
    geo_destination: str = ""


class SensitiveDataRecord(BaseModel):
    """A classified piece of sensitive data found in a flow."""

    id: str = ""
    flow_id: str = ""
    data_type: str = ""  # PII / PHI / PCI / secrets / IP
    sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    pattern_matched: str = ""
    confidence: float = 0.0
    sample_hash: str = ""
    regulation: str = ""  # GDPR / HIPAA / PCI_DSS / CCPA


class ExfiltrationAttempt(BaseModel):
    """A detected data exfiltration event."""

    id: str = ""
    flow_id: str = ""
    channel: ExfiltrationChannel = ExfiltrationChannel.ENDPOINT
    severity: str = "medium"  # low / medium / high / critical
    technique: str = ""
    data_types_involved: list[str] = Field(default_factory=list)
    volume_mb: float = 0.0
    user_identity: str = ""
    blocked: bool = False
    confidence: float = 0.0
    mitre_tactic: str = ""  # T1041 / T1048 / T1567 etc.


class DLPPolicy(BaseModel):
    """A data loss prevention policy enforcement record."""

    id: str = ""
    policy_name: str = ""
    channel: ExfiltrationChannel = ExfiltrationChannel.ENDPOINT
    action: str = "alert"  # alert / block / quarantine / encrypt
    sensitivity_threshold: DataSensitivity = DataSensitivity.CONFIDENTIAL
    applied: bool = False
    matches: int = 0
    false_positives: int = 0


class IncidentResponse(BaseModel):
    """A DLP incident response action taken."""

    id: str = ""
    exfiltration_id: str = ""
    action_taken: str = ""  # block / revoke / quarantine / notify
    success: bool = False
    response_time_ms: float = 0.0
    escalated: bool = False
    containment_status: str = "open"  # open / contained / resolved


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DataLossPreventionState(BaseModel):
    """Main state for the Data Loss Prevention graph."""

    # Input
    request_id: str = ""
    stage: DLPStage = DLPStage.DISCOVER_DATA_FLOWS
    tenant_id: str = ""

    # Data
    data_flows_discovered: list[dict[str, Any]] = Field(default_factory=list)
    sensitive_records: list[dict[str, Any]] = Field(default_factory=list)
    exfiltration_attempts: list[dict[str, Any]] = Field(default_factory=list)
    policies_enforced: list[dict[str, Any]] = Field(default_factory=list)
    incidents_responded: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    data_at_risk_gb: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
