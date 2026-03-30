"""Network Traffic Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class NTAStage(StrEnum):
    """Stages in the network traffic analysis workflow."""

    CAPTURE_FLOWS = "capture_flows"
    ANALYZE_PATTERNS = "analyze_patterns"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY_THREATS = "classify_threats"
    ENFORCE_POLICIES = "enforce_policies"
    REPORT = "report"


class TrafficCategory(StrEnum):
    """Categories for network traffic classification."""

    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ENCRYPTED = "encrypted"
    UNKNOWN = "unknown"


class ThreatType(StrEnum):
    """Types of network-based threats."""

    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    C2_COMMUNICATION = "c2_communication"
    PORT_SCAN = "port_scan"
    DNS_TUNNELING = "dns_tunneling"
    BRUTE_FORCE = "brute_force"


class NetworkFlow(BaseModel):
    """A single network traffic flow record."""

    id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 0
    duration_ms: int = 0
    timestamp: float = 0.0
    flags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TrafficPattern(BaseModel):
    """Detected traffic pattern from flow analysis."""

    id: str = ""
    pattern_name: str = ""
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    protocol: str = ""
    flow_count: int = 0
    total_bytes: int = 0
    category: TrafficCategory = TrafficCategory.UNKNOWN
    description: str = ""


class TrafficAnomaly(BaseModel):
    """Anomaly detected in network traffic."""

    id: str = ""
    threat_type: ThreatType = ThreatType.PORT_SCAN
    severity: str = "medium"
    confidence: float = 0.0
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    description: str = ""
    mitre_tactic: str = ""


class ThreatClassification(BaseModel):
    """Classified threat from correlated anomalies."""

    id: str = ""
    threat_name: str = ""
    threat_type: ThreatType = ThreatType.PORT_SCAN
    severity: str = "medium"
    confidence: float = 0.0
    kill_chain_phase: str = ""
    recommended_action: str = ""
    evidence: list[str] = Field(default_factory=list)
    llm_reasoning: str = ""


class PolicyEnforcement(BaseModel):
    """Policy enforcement action on detected threats."""

    id: str = ""
    threat_id: str = ""
    action: str = ""
    target_ips: list[str] = Field(default_factory=list)
    rule_name: str = ""
    status: str = "pending"
    reason: str = ""


class ReasoningStep(BaseModel):
    """A single reasoning step in the agent chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class NetworkTrafficAnalyzerState(BaseModel):
    """Full state for the Network Traffic Analyzer agent."""

    request_id: str = ""
    stage: NTAStage = NTAStage.CAPTURE_FLOWS
    tenant_id: str = ""

    # Input
    raw_flows: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Captured flows
    flows: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Patterns
    patterns: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Anomalies
    anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Threat classifications
    threats: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Policy enforcements
    enforcements: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Stats and reporting
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )

    # Workflow metadata
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
