"""OT Protocol Monitor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OPMStage(StrEnum):
    DISCOVER_DEVICES = "discover_devices"
    MONITOR_PROTOCOLS = "monitor_protocols"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY_THREATS = "classify_threats"
    ALERT = "alert"
    REPORT = "report"


class OTProtocolType(StrEnum):
    MODBUS = "modbus"
    DNP3 = "dnp3"
    OPC_UA = "opc_ua"
    BACNET = "bacnet"
    ETHERNET_IP = "ethernet_ip"
    PROFINET = "profinet"


class OTThreatSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OTDevice(BaseModel):
    """A discovered OT/ICS device."""

    id: str = ""
    name: str = ""
    device_type: str = ""
    ip_address: str = ""
    protocol: OTProtocolType = OTProtocolType.MODBUS
    vendor: str = ""
    firmware_version: str = ""
    last_seen: str = ""
    zone: str = ""
    is_critical: bool = False


class ProtocolEvent(BaseModel):
    """A single OT protocol event."""

    id: str = ""
    timestamp: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    protocol: OTProtocolType = OTProtocolType.MODBUS
    function_code: int = 0
    payload_size: int = 0
    register_address: int = 0
    value: float = 0.0
    is_write: bool = False


class ProtocolAnomaly(BaseModel):
    """A detected protocol anomaly."""

    id: str = ""
    device_id: str = ""
    protocol: OTProtocolType = OTProtocolType.MODBUS
    anomaly_type: str = ""
    description: str = ""
    confidence: float = 0.0
    baseline_value: float = 0.0
    observed_value: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class OTThreat(BaseModel):
    """A classified OT/ICS threat."""

    id: str = ""
    anomaly_id: str = ""
    threat_type: str = ""
    severity: OTThreatSeverity = OTThreatSeverity.MEDIUM
    attack_vector: str = ""
    affected_devices: list[str] = Field(default_factory=list)
    mitre_ics_tactic: str = ""
    confidence: float = 0.0


class OTAlert(BaseModel):
    """An OT security alert."""

    id: str = ""
    threat_id: str = ""
    severity: OTThreatSeverity = OTThreatSeverity.MEDIUM
    title: str = ""
    description: str = ""
    recommended_action: str = ""
    notified: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class OTProtocolMonitorState(BaseModel):
    """Main state for the OT Protocol Monitor agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: OPMStage = OPMStage.DISCOVER_DEVICES

    devices: list[OTDevice] = Field(default_factory=list)
    events: list[ProtocolEvent] = Field(default_factory=list)
    anomalies: list[ProtocolAnomaly] = Field(default_factory=list)
    threats: list[OTThreat] = Field(default_factory=list)
    alerts: list[OTAlert] = Field(default_factory=list)

    report: str = ""
    total_devices_scanned: int = 0
    anomalies_detected: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
