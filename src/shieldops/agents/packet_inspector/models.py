"""Packet Inspector Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class InspectionStage(StrEnum):
    CAPTURE_PACKETS = "capture_packets"
    DECODE_PROTOCOL = "decode_protocol"
    ANALYZE_PAYLOAD = "analyze_payload"
    VALIDATE_TLS = "validate_tls"
    DETECT_THREATS = "detect_threats"
    REPORT = "report"


class PayloadRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BENIGN = "benign"


class TLSStatus(StrEnum):
    VALID = "valid"
    EXPIRED = "expired"
    SELF_SIGNED = "self_signed"
    REVOKED = "revoked"
    WEAK_CIPHER = "weak_cipher"
    MISSING = "missing"


class PacketCapture(BaseModel):
    """A captured network packet for inspection."""

    id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    payload_size_bytes: int = 0
    timestamp: float = 0.0
    direction: str = ""
    interface: str = ""
    flags: list[str] = Field(default_factory=list)
    raw_hex: str = ""


class PayloadAnalysis(BaseModel):
    """Results from payload content analysis."""

    packet_id: str = ""
    protocol_decoded: str = ""
    content_type: str = ""
    payload_entropy: float = 0.0
    is_encrypted: bool = False
    suspicious_patterns: list[str] = Field(default_factory=list)
    extracted_strings: list[str] = Field(default_factory=list)
    matched_signatures: list[str] = Field(default_factory=list)
    risk: PayloadRisk = PayloadRisk.BENIGN
    risk_score: float = 0.0
    llm_reasoning: str = ""


class TLSCertCheck(BaseModel):
    """TLS certificate validation result."""

    packet_id: str = ""
    server_name: str = ""
    issuer: str = ""
    subject: str = ""
    not_before: str = ""
    not_after: str = ""
    serial_number: str = ""
    cipher_suite: str = ""
    tls_version: str = ""
    status: TLSStatus = TLSStatus.VALID
    chain_valid: bool = True
    pinning_match: bool = True
    ja3_fingerprint: str = ""
    ja3s_fingerprint: str = ""


class ThreatDetection(BaseModel):
    """A detected threat from packet analysis."""

    packet_id: str = ""
    threat_type: str = ""
    description: str = ""
    severity: PayloadRisk = PayloadRisk.MEDIUM
    mitre_technique: str = ""
    confidence: float = 0.0
    recommended_action: str = ""


class ReasoningStep(BaseModel):
    """A single reasoning step in the agent chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class PacketInspectorState(BaseModel):
    """Full state for the Packet Inspector agent."""

    request_id: str = ""
    stage: InspectionStage = InspectionStage.CAPTURE_PACKETS
    tenant_id: str = ""
    packets: list[dict[str, Any]] = Field(default_factory=list)
    packets_inspected: int = 0
    payload_analyses: list[dict[str, Any]] = Field(default_factory=list)
    tls_checks: list[dict[str, Any]] = Field(default_factory=list)
    threats_detected: list[dict[str, Any]] = Field(default_factory=list)
    threat_count: int = 0
    avg_payload_entropy: float = 0.0
    tls_valid_pct: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
