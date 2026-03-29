"""Mobile Device Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MDMStage(StrEnum):
    DISCOVER_DEVICES = "discover_devices"
    CHECK_ENROLLMENT = "check_enrollment"
    ASSESS_COMPLIANCE = "assess_compliance"
    ENFORCE_POLICIES = "enforce_policies"
    CHECK_APPS = "check_apps"
    REPORT = "report"


class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    PENDING = "pending"
    UNENROLLED = "unenrolled"


class DeviceAction(StrEnum):
    ENROLL = "enroll"
    LOCK = "lock"
    WIPE = "wipe"
    RESTRICT = "restrict"
    NOTIFY = "notify"
    ALLOW = "allow"


class MobileDevice(BaseModel):
    """A managed mobile device."""

    device_id: str = ""
    name: str = ""
    platform: str = ""
    os_version: str = ""
    owner: str = ""
    enrolled: bool = False
    encrypted: bool = False
    compliance: ComplianceStatus = ComplianceStatus.PENDING
    last_checkin: datetime | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class AppPolicy(BaseModel):
    """An application policy for mobile devices."""

    app_id: str = ""
    app_name: str = ""
    allowed: bool = True
    required: bool = False
    min_version: str = ""
    reason: str = ""


class ComplianceViolation(BaseModel):
    """A device compliance violation."""

    device_id: str = ""
    rule: str = ""
    expected: str = ""
    actual: str = ""
    severity: str = "medium"
    action_taken: DeviceAction = DeviceAction.NOTIFY


class MobileDeviceManagerState(BaseModel):
    """Main state for the Mobile Device Manager agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: MDMStage = MDMStage.DISCOVER_DEVICES

    # Discovery
    devices: list[dict[str, Any]] = Field(default_factory=list)
    total_devices: int = 0
    unenrolled_count: int = 0

    # Compliance
    violations: list[dict[str, Any]] = Field(default_factory=list)
    compliant_count: int = 0
    non_compliant_count: int = 0

    # Apps
    blocked_apps: list[dict[str, Any]] = Field(default_factory=list)

    # Enforcement
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    encryption_enforced: int = 0

    # Report
    summary: str = ""
    compliance_rate: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
