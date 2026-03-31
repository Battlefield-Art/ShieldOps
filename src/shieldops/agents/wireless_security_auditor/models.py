"""State models for the Wireless Security Auditor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class WSAStage(StrEnum):
    """Stages in the wireless security audit lifecycle."""

    DISCOVER_NETWORKS = "discover_networks"
    SCAN_ACCESS_POINTS = "scan_access_points"
    CHECK_ENCRYPTION = "check_encryption"
    DETECT_ROGUES = "detect_rogues"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class EncryptionProtocol(StrEnum):
    """WiFi encryption protocol."""

    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    WPA2_ENTERPRISE = "wpa2_enterprise"
    WPA3_ENTERPRISE = "wpa3_enterprise"


class APClassification(StrEnum):
    """Access point classification."""

    AUTHORIZED = "authorized"
    ROGUE = "rogue"
    EVIL_TWIN = "evil_twin"
    NEIGHBOR = "neighbor"
    UNKNOWN = "unknown"
    DECOMMISSIONED = "decommissioned"


# --- Domain models ---


class WirelessNetwork(BaseModel):
    """A discovered wireless network."""

    ssid: str = ""
    bssid: str = ""
    channel: int = 0
    signal_strength: int = 0
    encryption: EncryptionProtocol = EncryptionProtocol.OPEN
    band: str = "2.4GHz"
    hidden: bool = False
    clients_connected: int = 0


class AccessPoint(BaseModel):
    """A scanned wireless access point."""

    ap_id: str = ""
    ssid: str = ""
    bssid: str = ""
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    encryption: EncryptionProtocol = EncryptionProtocol.OPEN
    classification: APClassification = APClassification.UNKNOWN
    location: str = ""
    last_seen: datetime | None = None


class EncryptionFinding(BaseModel):
    """Encryption audit finding for an access point."""

    ap_id: str = ""
    ssid: str = ""
    current_protocol: EncryptionProtocol = EncryptionProtocol.OPEN
    recommended_protocol: EncryptionProtocol = EncryptionProtocol.WPA3
    is_compliant: bool = False
    weakness: str = ""
    severity: str = "medium"


class RogueAPDetection(BaseModel):
    """A rogue access point detection."""

    ap_id: str = ""
    ssid: str = ""
    bssid: str = ""
    classification: APClassification = APClassification.ROGUE
    confidence: float = 0.0
    threat_level: str = "medium"
    evidence: list[str] = Field(default_factory=list)


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the wireless audit workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class WirelessSecurityAuditorState(BaseModel):
    """Full state for a wireless security auditor run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: WSAStage = WSAStage.DISCOVER_NETWORKS

    # Inputs
    site_name: str = ""
    scan_scope: dict[str, Any] = Field(
        default_factory=dict,
    )
    known_ssids: list[str] = Field(
        default_factory=list,
    )
    compliance_standard: str = "wpa3"

    # Pipeline fields
    networks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    access_points: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    encryption_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    rogue_detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessment: dict[str, Any] = Field(
        default_factory=dict,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_networks: int = 0
    total_access_points: int = 0
    rogue_count: int = 0
    non_compliant_count: int = 0
    risk_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
