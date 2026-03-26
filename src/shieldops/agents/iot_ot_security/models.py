"""IoT/OT Security Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IoTStage(StrEnum):
    DISCOVER_DEVICES = "discover_devices"
    PROFILE_BEHAVIOR = "profile_behavior"
    DETECT_ANOMALIES = "detect_anomalies"
    ASSESS_VULNERABILITIES = "assess_vulnerabilities"
    ENFORCE_SEGMENTATION = "enforce_segmentation"
    REPORT = "report"


class DeviceCategory(StrEnum):
    IOT_SENSOR = "iot_sensor"
    OT_CONTROLLER = "ot_controller"
    EDGE_AI = "edge_ai"
    SMART_CAMERA = "smart_camera"
    MEDICAL_DEVICE = "medical_device"
    BUILDING_AUTOMATION = "building_automation"


class ThreatLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IoTDevice(BaseModel):
    """A discovered IoT or OT device on the network."""

    id: str = ""
    name: str = ""
    ip_address: str = ""
    mac_address: str = ""
    category: DeviceCategory = DeviceCategory.IOT_SENSOR
    manufacturer: str = ""
    firmware_version: str = ""
    protocol: str = ""
    is_managed: bool = False
    is_ai_connected: bool = False
    ml_pipeline: str = ""
    network_zone: str = ""
    last_seen: float = 0.0


class BehaviorProfile(BaseModel):
    """Behavioral baseline for a device."""

    device_id: str = ""
    normal_protocols: list[str] = Field(
        default_factory=list,
    )
    normal_destinations: list[str] = Field(
        default_factory=list,
    )
    avg_bytes_per_hour: float = 0.0
    peak_bytes_per_hour: float = 0.0
    expected_ports: list[int] = Field(
        default_factory=list,
    )
    ai_data_flow_pattern: str = ""
    baseline_confidence: float = 0.0


class DeviceAnomaly(BaseModel):
    """An anomaly detected on an IoT/OT device."""

    id: str = ""
    device_id: str = ""
    device_name: str = ""
    anomaly_type: str = ""
    description: str = ""
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    confidence: float = 0.0
    source_ip: str = ""
    dest_ip: str = ""
    protocol: str = ""
    timestamp: float = 0.0


class DeviceVulnerability(BaseModel):
    """A vulnerability found on an IoT/OT device."""

    id: str = ""
    device_id: str = ""
    device_name: str = ""
    cve_id: str = ""
    severity: ThreatLevel = ThreatLevel.MEDIUM
    cvss_score: float = 0.0
    firmware_affected: str = ""
    patch_available: bool = False
    description: str = ""
    exploitable: bool = False


class SegmentationPolicy(BaseModel):
    """A micro-segmentation policy for device network isolation."""

    id: str = ""
    device_id: str = ""
    device_name: str = ""
    source_zone: str = ""
    dest_zone: str = ""
    allowed_protocols: list[str] = Field(
        default_factory=list,
    )
    allowed_ports: list[int] = Field(
        default_factory=list,
    )
    action: str = "deny"
    applied: bool = False
    success: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )


class IoTOTSecurityState(BaseModel):
    """Main state for the IoT/OT Security graph."""

    # Input
    request_id: str = ""
    stage: IoTStage = IoTStage.DISCOVER_DEVICES
    tenant_id: str = ""
    network_zones: list[str] = Field(
        default_factory=lambda: ["iot", "ot", "edge"],
    )

    # Collected data
    devices_discovered: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    profiles_built: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomalies_detected: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    vulnerabilities_found: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    policies_enforced: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    unmanaged_devices: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metadata
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
