"""State models for the Mobile Threat Defender Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class MTDStage(StrEnum):
    """Workflow stages for mobile threat defense."""

    SCAN_DEVICE = "scan_device"
    ANALYZE_APPS = "analyze_apps"
    CHECK_NETWORK = "check_network"
    DETECT_THREATS = "detect_threats"
    ENFORCE_POLICY = "enforce_policy"
    REPORT = "report"


class DevicePlatform(StrEnum):
    """Mobile device operating system platforms."""

    IOS = "ios"
    ANDROID = "android"
    CHROME_OS = "chrome_os"
    WINDOWS_MOBILE = "windows_mobile"
    LINUX_MOBILE = "linux_mobile"
    UNKNOWN = "unknown"


class ThreatCategory(StrEnum):
    """Categories of mobile threats detected."""

    MALWARE = "malware"
    PHISHING = "phishing"
    NETWORK_ATTACK = "network_attack"
    ROOT_JAILBREAK = "root_jailbreak"
    DATA_LEAKAGE = "data_leakage"
    SIDE_LOADED_APP = "side_loaded_app"
    VULNERABLE_OS = "vulnerable_os"


# ── Domain Models ─────────────────────────────────────


class DeviceScan(BaseModel):
    """Result of a mobile device posture scan."""

    device_id: str = ""
    platform: DevicePlatform = DevicePlatform.UNKNOWN
    os_version: str = ""
    is_rooted: bool = False
    is_jailbroken: bool = False
    encryption_enabled: bool = True
    screen_lock_enabled: bool = True
    mdm_enrolled: bool = False
    last_patch_date: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AppAnalysis(BaseModel):
    """Analysis result for a mobile application."""

    app_id: str = ""
    package_name: str = ""
    app_name: str = ""
    version: str = ""
    reputation_score: float = 0.0
    permissions: list[str] = Field(default_factory=list)
    is_side_loaded: bool = False
    is_malicious: bool = False
    risk_level: str = "low"
    findings: list[str] = Field(default_factory=list)


class NetworkCheck(BaseModel):
    """Network security check result for a device."""

    check_id: str = ""
    device_id: str = ""
    vpn_active: bool = False
    wifi_secure: bool = True
    mitm_detected: bool = False
    ssl_stripping: bool = False
    rogue_ap_detected: bool = False
    dns_poisoning: bool = False
    details: str = ""


class MobileThreat(BaseModel):
    """A detected mobile threat."""

    threat_id: str = ""
    device_id: str = ""
    category: ThreatCategory = ThreatCategory.MALWARE
    severity: str = "medium"
    confidence: float = 0.0
    description: str = ""
    indicators: list[str] = Field(default_factory=list)
    recommended_action: str = ""


class PolicyEnforcement(BaseModel):
    """A policy enforcement action taken on a device."""

    action_id: str = ""
    device_id: str = ""
    policy_name: str = ""
    action_taken: str = ""
    success: bool = True
    details: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the defender workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class MobileThreatDefenderState(BaseModel):
    """Full state for the Mobile Threat Defender workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: MTDStage = MTDStage.SCAN_DEVICE
    defend_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Device scans
    device_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    compromised_device_count: int = 0

    # App analysis
    app_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    malicious_app_count: int = 0

    # Network checks
    network_checks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    network_threat_count: int = 0

    # Threats
    detected_threats: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    max_threat_severity: str = "low"

    # Policy enforcement
    policy_actions: list[dict[str, Any]] = Field(
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
