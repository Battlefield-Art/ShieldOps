"""Network Forensics Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ForensicsStage(StrEnum):
    INGEST_CAPTURE = "ingest_capture"
    RECONSTRUCT_SESSIONS = "reconstruct_sessions"
    BUILD_TIMELINE = "build_timeline"
    TRACE_LATERAL = "trace_lateral"
    MAP_EXFILTRATION = "map_exfiltration"
    REPORT = "report"


class EvidenceType(StrEnum):
    PCAP = "pcap"
    NETFLOW = "netflow"
    ZEEK_LOG = "zeek_log"
    DNS_LOG = "dns_log"
    FIREWALL_LOG = "firewall_log"
    PROXY_LOG = "proxy_log"
    IDS_ALERT = "ids_alert"
    SYSLOG = "syslog"


class SessionType(StrEnum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SMB = "smb"
    SSH = "ssh"
    RDP = "rdp"
    FTP = "ftp"
    SMTP = "smtp"
    ICMP = "icmp"
    CUSTOM = "custom"


class NetworkSession(BaseModel):
    """A reconstructed network session from captured traffic."""

    id: str = ""
    session_type: SessionType = SessionType.HTTP
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0
    packet_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    flags: list[str] = Field(default_factory=list)
    payload_preview: str = ""
    is_encrypted: bool = False
    tls_version: str = ""
    server_name: str = ""
    user_agent: str = ""
    http_method: str = ""
    http_uri: str = ""
    dns_query: str = ""
    dns_response: str = ""


class ForensicEvidence(BaseModel):
    """A piece of network forensic evidence."""

    id: str = ""
    evidence_type: EvidenceType = EvidenceType.PCAP
    source_file: str = ""
    timestamp: float = 0.0
    description: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    severity: str = ""
    ioc_matches: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    raw_data: str = ""
    confidence: float = 0.0


class ExfilPath(BaseModel):
    """A detected data exfiltration path."""

    id: str = ""
    src_host: str = ""
    dst_host: str = ""
    dst_ip: str = ""
    protocol: str = ""
    port: int = 0
    method: str = ""
    bytes_exfiltrated: int = 0
    duration_seconds: float = 0.0
    encoding: str = ""
    is_encrypted: bool = False
    confidence: float = 0.0
    sessions: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class TimelineEvent(BaseModel):
    """A single event in the forensic timeline."""

    timestamp: float = 0.0
    event_type: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    description: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    severity: str = ""


class LateralMovement(BaseModel):
    """A detected lateral movement hop."""

    src_host: str = ""
    dst_host: str = ""
    protocol: str = ""
    method: str = ""
    timestamp: float = 0.0
    credential_used: str = ""
    mitre_technique: str = ""
    confidence: float = 0.0


class ReasoningStep(BaseModel):
    """A single reasoning step in the agent chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class NetworkForensicsState(BaseModel):
    """Full state for the Network Forensics agent."""

    request_id: str = ""
    stage: ForensicsStage = ForensicsStage.INGEST_CAPTURE
    tenant_id: str = ""
    captures: list[dict[str, Any]] = Field(default_factory=list)
    captures_ingested: int = 0
    sessions: list[dict[str, Any]] = Field(default_factory=list)
    sessions_reconstructed: int = 0
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    lateral_movements: list[dict[str, Any]] = Field(default_factory=list)
    exfil_paths: list[dict[str, Any]] = Field(default_factory=list)
    total_bytes_analyzed: int = 0
    total_packets_analyzed: int = 0
    suspicious_sessions: int = 0
    exfil_bytes_detected: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
