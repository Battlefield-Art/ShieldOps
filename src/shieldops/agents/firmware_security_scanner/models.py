"""State models for the Firmware Security Scanner Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class FSSStage(StrEnum):
    """Workflow stages for firmware security scanning."""

    EXTRACT_FIRMWARE = "extract_firmware"
    ANALYZE_COMPONENTS = "analyze_components"
    SCAN_VULNS = "scan_vulns"
    CHECK_CRYPTO = "check_crypto"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class FirmwareType(StrEnum):
    """Types of firmware images analyzed."""

    IOT_DEVICE = "iot_device"
    OT_CONTROLLER = "ot_controller"
    NETWORK_APPLIANCE = "network_appliance"
    EMBEDDED_SYSTEM = "embedded_system"
    ROUTER = "router"
    CAMERA = "camera"
    SENSOR = "sensor"


class CryptoStrength(StrEnum):
    """Cryptographic strength classification."""

    STRONG = "strong"
    ADEQUATE = "adequate"
    WEAK = "weak"
    DEPRECATED = "deprecated"
    NONE = "none"


# ── Domain Models ─────────────────────────────────────


class FirmwareImage(BaseModel):
    """An extracted firmware image for analysis."""

    firmware_id: str = ""
    device_vendor: str = ""
    device_model: str = ""
    firmware_version: str = ""
    firmware_type: FirmwareType = FirmwareType.IOT_DEVICE
    file_size_bytes: int = 0
    architecture: str = ""
    os_type: str = ""
    extracted_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FirmwareComponent(BaseModel):
    """A component extracted from firmware (SBOM entry)."""

    component_id: str = ""
    firmware_id: str = ""
    name: str = ""
    version: str = ""
    license_type: str = ""
    is_outdated: bool = False
    known_vulns: int = 0
    source: str = ""
    findings: list[str] = Field(default_factory=list)


class VulnerabilityMatch(BaseModel):
    """A CVE match found in firmware components."""

    vuln_id: str = ""
    firmware_id: str = ""
    component_name: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    severity: str = "medium"
    exploitable: bool = False
    patch_available: bool = False
    description: str = ""


class CryptoFinding(BaseModel):
    """A cryptographic weakness found in firmware."""

    finding_id: str = ""
    firmware_id: str = ""
    algorithm: str = ""
    key_size: int = 0
    strength: CryptoStrength = CryptoStrength.ADEQUATE
    location: str = ""
    recommendation: str = ""
    findings: list[str] = Field(default_factory=list)


class FirmwareRiskAssessment(BaseModel):
    """Overall risk assessment for a firmware image."""

    firmware_id: str = ""
    risk_score: float = 0.0
    vuln_count: int = 0
    critical_vuln_count: int = 0
    weak_crypto_count: int = 0
    outdated_components: int = 0
    reasoning: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the firmware scanner workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class FirmwareSecurityScannerState(BaseModel):
    """Full state for the Firmware Security Scanner workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: FSSStage = FSSStage.EXTRACT_FIRMWARE
    scan_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Extraction
    firmware_images: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_extracted: int = 0

    # Components
    components: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    outdated_component_count: int = 0

    # Vulnerabilities
    vulnerabilities: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    critical_vuln_count: int = 0

    # Crypto
    crypto_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    weak_crypto_count: int = 0

    # Risk
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    max_risk_score: float = 0.0

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
