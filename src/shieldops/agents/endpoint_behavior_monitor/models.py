"""Endpoint Behavior Monitor Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MonitorStage(StrEnum):
    COLLECT_TELEMETRY = "collect_telemetry"
    ANALYZE_PROCESSES = "analyze_processes"
    CHECK_FILESYSTEM = "check_filesystem"
    INSPECT_REGISTRY = "inspect_registry"
    INSPECT_NETWORK = "inspect_network"
    CHECK_USB = "check_usb"
    CORRELATE = "correlate"
    REPORT = "report"


class AnomalyType(StrEnum):
    PROCESS_INJECTION = "process_injection"
    SUSPICIOUS_EXECUTION = "suspicious_execution"
    FILE_TAMPERING = "file_tampering"
    REGISTRY_MODIFICATION = "registry_modification"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    USB_VIOLATION = "usb_violation"
    NORMAL = "normal"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ProcessEvent(BaseModel):
    """A process execution event on an endpoint."""

    pid: int = 0
    name: str = ""
    path: str = ""
    command_line: str = ""
    parent_pid: int = 0
    parent_name: str = ""
    user: str = ""
    severity: Severity = Severity.INFO
    anomaly_type: AnomalyType = AnomalyType.NORMAL
    timestamp: datetime | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class FileSystemEvent(BaseModel):
    """A file system change event."""

    path: str = ""
    action: str = ""
    old_hash: str = ""
    new_hash: str = ""
    user: str = ""
    severity: Severity = Severity.INFO
    timestamp: datetime | None = None


class NetworkConnection(BaseModel):
    """A network connection event."""

    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    process_name: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0
    severity: Severity = Severity.INFO
    timestamp: datetime | None = None


class EndpointBehaviorMonitorState(BaseModel):
    """Main state for the Endpoint Behavior Monitor agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    endpoint_id: str = ""
    stage: MonitorStage = MonitorStage.COLLECT_TELEMETRY

    # Telemetry
    process_events: list[dict[str, Any]] = Field(default_factory=list)
    filesystem_events: list[dict[str, Any]] = Field(default_factory=list)
    registry_events: list[dict[str, Any]] = Field(default_factory=list)
    network_events: list[dict[str, Any]] = Field(default_factory=list)
    usb_events: list[dict[str, Any]] = Field(default_factory=list)

    # Analysis
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    total_events: int = 0
    anomaly_count: int = 0
    risk_score: float = 0.0

    # Report
    summary: str = ""
    recommendations: list[str] = Field(default_factory=list)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
