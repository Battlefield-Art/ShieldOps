"""State models for the Data Exfiltration Monitor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class DEMStage(StrEnum):
    """Workflow stages for data exfiltration monitoring."""

    MONITOR_CHANNELS = "monitor_channels"
    ANALYZE_FLOWS = "analyze_flows"
    DETECT_EXFIL = "detect_exfil"
    CLASSIFY_SENSITIVITY = "classify_sensitivity"
    BLOCK = "block"
    REPORT = "report"


class DataSensitivity(StrEnum):
    """Data sensitivity classification levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class ExfilChannel(StrEnum):
    """Exfiltration channel types."""

    NETWORK = "network"
    USB = "usb"
    CLOUD_UPLOAD = "cloud_upload"
    EMAIL = "email"
    ENCRYPTED_TUNNEL = "encrypted_tunnel"
    DNS_TUNNEL = "dns_tunnel"
    PRINT = "print"


# -- Domain Models -----------------------------------------------------


class DataFlow(BaseModel):
    """A monitored data flow across channels."""

    flow_id: str = ""
    channel: ExfilChannel = ExfilChannel.NETWORK
    source_ip: str = ""
    destination_ip: str = ""
    bytes_transferred: int = 0
    protocol: str = ""
    user_id: str = ""
    timestamp: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExfilDetection(BaseModel):
    """A detected exfiltration attempt."""

    detection_id: str = ""
    flow_id: str = ""
    channel: ExfilChannel = ExfilChannel.NETWORK
    confidence: float = 0.0
    technique: str = ""
    data_volume_bytes: int = 0
    risk_score: float = 0.0
    indicators: list[str] = Field(default_factory=list)


class SensitivityClassification(BaseModel):
    """Sensitivity classification for detected data."""

    classification_id: str = ""
    detection_id: str = ""
    sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    data_types: list[str] = Field(default_factory=list)
    pii_detected: bool = False
    regex_matches: int = 0
    reasoning: str = ""


class BlockAction(BaseModel):
    """A blocking action taken against exfiltration."""

    action_id: str = ""
    detection_id: str = ""
    action_type: str = "block"
    success: bool = False
    details: str = ""


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the monitor workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class DataExfiltrationMonitorState(BaseModel):
    """Full state for the Data Exfiltration Monitor workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: DEMStage = DEMStage.MONITOR_CHANNELS
    monitor_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Monitoring
    data_flows: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    channel_count: int = 0

    # Detection
    detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    exfil_count: int = 0

    # Classification
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    sensitive_count: int = 0

    # Blocking
    block_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    blocked_count: int = 0

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
