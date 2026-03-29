"""USB Device Controller Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class USBStage(StrEnum):
    SCAN_DEVICES = "scan_devices"
    CHECK_WHITELIST = "check_whitelist"
    MONITOR_TRANSFERS = "monitor_transfers"
    ENFORCE_POLICY = "enforce_policy"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class DeviceClassification(StrEnum):
    WHITELISTED = "whitelisted"
    UNAUTHORIZED = "unauthorized"
    PENDING_REVIEW = "pending_review"  # noqa: S105
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class TransferRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class USBDevice(BaseModel):
    """A USB device connected to an endpoint."""

    device_id: str = ""
    vendor_id: str = ""
    product_id: str = ""
    serial: str = ""
    device_name: str = ""
    device_type: str = ""
    endpoint_id: str = ""
    user: str = ""
    classification: DeviceClassification = DeviceClassification.UNKNOWN
    connected_at: datetime | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class DataTransfer(BaseModel):
    """A data transfer event involving USB."""

    id: str = ""
    device_id: str = ""
    endpoint_id: str = ""
    direction: str = ""
    file_name: str = ""
    file_size: int = 0
    file_type: str = ""
    risk: TransferRisk = TransferRisk.LOW
    blocked: bool = False
    timestamp: datetime | None = None


class USBPolicy(BaseModel):
    """A USB device control policy."""

    id: str = ""
    name: str = ""
    device_type: str = ""
    action: str = ""
    reason: str = ""
    enabled: bool = True


class USBDeviceControllerState(BaseModel):
    """Main state for the USB Device Controller agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: USBStage = USBStage.SCAN_DEVICES

    # Scanning
    connected_devices: list[dict[str, Any]] = Field(default_factory=list)
    total_devices: int = 0

    # Whitelist
    unauthorized_devices: list[dict[str, Any]] = Field(default_factory=list)
    whitelisted_count: int = 0
    unauthorized_count: int = 0

    # Transfers
    transfers: list[dict[str, Any]] = Field(default_factory=list)
    blocked_transfers: int = 0
    suspicious_transfers: int = 0

    # Policy
    enforcements: list[dict[str, Any]] = Field(default_factory=list)
    policies_applied: int = 0

    # Risk
    risk_score: float = 0.0
    summary: str = ""
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
