"""State models for the Network Traffic Analyzer Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalysisStage(StrEnum):
    """Stages in the network traffic analysis workflow."""

    INGEST_FLOWS = "ingest_flows"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY_THREATS = "classify_threats"
    ANALYZE_PROTOCOLS = "analyze_protocols"
    CORRELATE = "correlate"
    REPORT = "report"


class TrafficAnomalyType(StrEnum):
    """Types of network traffic anomalies."""

    LATERAL_MOVEMENT = "lateral_movement"
    C2_BEACON = "c2_beacon"
    DATA_EXFILTRATION = "data_exfiltration"
    DNS_TUNNELING = "dns_tunneling"
    PORT_SCAN = "port_scan"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    BANDWIDTH_SPIKE = "bandwidth_spike"
    BEACONING = "beaconing"


class ProtocolType(StrEnum):
    """Network protocol types for analysis."""

    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SSH = "ssh"
    TLS = "tls"
    ICMP = "icmp"


class TrafficFlow(BaseModel):
    """A single network traffic flow record."""

    id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: ProtocolType = ProtocolType.TCP
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 0
    duration_ms: int = 0
    timestamp: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnomalyDetection(BaseModel):
    """Result of anomaly detection on traffic flows."""

    id: str = ""
    anomaly_type: TrafficAnomalyType = TrafficAnomalyType.PORT_SCAN
    severity: str = "medium"
    confidence: float = 0.0
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    description: str = ""
    indicators: list[str] = Field(default_factory=list)
    mitre_tactic: str = ""


class ProtocolAnalysis(BaseModel):
    """Analysis result for a specific protocol."""

    id: str = ""
    protocol: ProtocolType = ProtocolType.TCP
    total_flows: int = 0
    total_bytes: int = 0
    anomalous_flows: int = 0
    top_talkers: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)


class ThreatClassification(BaseModel):
    """Classified threat from correlated anomalies."""

    id: str = ""
    threat_name: str = ""
    anomaly_type: TrafficAnomalyType = TrafficAnomalyType.PORT_SCAN
    severity: str = "medium"
    confidence: float = 0.0
    kill_chain_phase: str = ""
    recommended_action: str = ""
    evidence: list[str] = Field(default_factory=list)


class NetworkTrafficAnalyzerState(BaseModel):
    """Full state for the Network Traffic Analyzer workflow."""

    request_id: str = ""
    stage: AnalysisStage = AnalysisStage.INGEST_FLOWS
    tenant_id: str = ""

    # Input
    raw_flows: list[dict[str, Any]] = Field(default_factory=list)

    # Ingested flows
    flows: list[TrafficFlow] = Field(default_factory=list)

    # Anomaly detection
    anomalies: list[AnomalyDetection] = Field(default_factory=list)

    # Threat classification
    threats: list[ThreatClassification] = Field(default_factory=list)

    # Protocol analysis
    protocol_analyses: list[ProtocolAnalysis] = Field(
        default_factory=list,
    )

    # Correlation
    correlations: list[dict[str, Any]] = Field(default_factory=list)

    # Stats & reporting
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)

    # Workflow metadata
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: int = 0
    error: str = ""
