"""State models for the Network Traffic Inspector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class NTIStage(StrEnum):
    """Workflow stages for network traffic inspection."""

    CAPTURE_TRAFFIC = "capture_traffic"
    ANALYZE_PROTOCOLS = "analyze_protocols"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY_THREATS = "classify_threats"
    ALERT = "alert"
    REPORT = "report"


class ProtocolCategory(StrEnum):
    """Network protocol categories."""

    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    SSH = "ssh"
    SMTP = "smtp"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class ThreatClass(StrEnum):
    """Threat classification for detected anomalies."""

    C2_BEACON = "c2_beacon"
    DNS_TUNNELING = "dns_tunneling"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    BENIGN = "benign"


# -- Domain Models -----------------------------------------------------


class CapturedFlow(BaseModel):
    """A captured network flow for analysis."""

    flow_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: ProtocolCategory = ProtocolCategory.UNKNOWN
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets: int = 0
    duration_ms: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProtocolAnalysis(BaseModel):
    """Analysis result for a protocol conversation."""

    flow_id: str = ""
    protocol: ProtocolCategory = ProtocolCategory.UNKNOWN
    is_encrypted: bool = False
    is_standard_port: bool = True
    payload_entropy: float = 0.0
    anomaly_indicators: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)


class DetectedAnomaly(BaseModel):
    """An anomaly detected in network traffic."""

    anomaly_id: str = ""
    flow_id: str = ""
    anomaly_type: str = ""
    confidence: float = 0.0
    description: str = ""
    indicators: list[str] = Field(default_factory=list)


class ThreatClassification(BaseModel):
    """Classification of a detected threat."""

    threat_id: str = ""
    anomaly_id: str = ""
    threat_class: ThreatClass = ThreatClass.BENIGN
    severity: str = "low"
    confidence: float = 0.0
    mitre_technique: str = ""
    description: str = ""


class GeneratedAlert(BaseModel):
    """An alert generated from threat classification."""

    alert_id: str = ""
    threat_id: str = ""
    severity: str = "low"
    title: str = ""
    description: str = ""
    recommended_action: str = ""


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the inspector workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class NetworkTrafficInspectorState(BaseModel):
    """Full state for the Network Traffic Inspector workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: NTIStage = NTIStage.CAPTURE_TRAFFIC
    capture_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Capture
    captured_flows: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_bytes: int = 0

    # Protocol analysis
    protocol_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomalous_protocol_count: int = 0

    # Anomaly detection
    detected_anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    high_confidence_count: int = 0

    # Threat classification
    threat_classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    critical_threat_count: int = 0

    # Alerts
    generated_alerts: list[dict[str, Any]] = Field(
        default_factory=list,
    )

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
