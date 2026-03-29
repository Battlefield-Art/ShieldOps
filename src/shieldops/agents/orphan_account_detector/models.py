"""Orphan Account Detector Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DetectionStage(StrEnum):
    SCAN_ACCOUNTS = "scan_accounts"
    CROSS_REFERENCE_HR = "cross_reference_hr"
    IDENTIFY_ORPHANS = "identify_orphans"
    CLASSIFY_RISK = "classify_risk"
    REMEDIATE = "remediate"
    REPORT = "report"


class AccountType(StrEnum):
    USER = "user"
    SERVICE = "service"
    SHARED = "shared"
    ADMIN = "admin"
    VENDOR = "vendor"
    SYSTEM = "system"


class OrphanReason(StrEnum):
    DEPARTED_EMPLOYEE = "departed_employee"
    ROLE_CHANGE = "role_change"
    MERGER = "merger"
    UNKNOWN_OWNER = "unknown_owner"
    STALE = "stale"
    DUPLICATE = "duplicate"


class OrphanAccountDetectorState(BaseModel):
    request_id: str = ""
    stage: DetectionStage = DetectionStage.SCAN_ACCOUNTS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
