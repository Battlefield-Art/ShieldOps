"""Patch Compliance Checker Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PatchStage(StrEnum):
    INVENTORY_SYSTEMS = "inventory_systems"
    SCAN_PATCHES = "scan_patches"
    ASSESS_RISK = "assess_risk"
    CHECK_SLA = "check_sla"
    SCHEDULE_ROLLOUT = "schedule_rollout"
    REPORT = "report"


class PatchSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class PatchStatus(StrEnum):
    MISSING = "missing"
    INSTALLED = "installed"
    PENDING = "pending"
    FAILED = "failed"
    SCHEDULED = "scheduled"
    EXCLUDED = "excluded"


class SystemInventory(BaseModel):
    """An endpoint in the fleet."""

    system_id: str = ""
    hostname: str = ""
    os: str = ""
    os_version: str = ""
    last_scan: datetime | None = None
    environment: str = ""
    criticality: str = ""
    context: dict[str, Any] = Field(default_factory=dict)


class MissingPatch(BaseModel):
    """A missing patch on a system."""

    patch_id: str = ""
    system_id: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    severity: PatchSeverity = PatchSeverity.MEDIUM
    title: str = ""
    published_date: datetime | None = None
    days_overdue: int = 0
    status: PatchStatus = PatchStatus.MISSING


class RolloutSchedule(BaseModel):
    """A patch rollout schedule entry."""

    id: str = ""
    patch_id: str = ""
    target_systems: list[str] = Field(default_factory=list)
    scheduled_at: datetime | None = None
    window: str = ""
    priority: int = 0


class PatchComplianceCheckerState(BaseModel):
    """Main state for the Patch Compliance Checker agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: PatchStage = PatchStage.INVENTORY_SYSTEMS

    # Inventory
    systems: list[dict[str, Any]] = Field(default_factory=list)
    total_systems: int = 0

    # Patches
    missing_patches: list[dict[str, Any]] = Field(default_factory=list)
    total_missing: int = 0
    critical_missing: int = 0

    # Risk
    risk_assessments: list[dict[str, Any]] = Field(default_factory=list)
    fleet_risk_score: float = 0.0

    # SLA
    sla_violations: list[dict[str, Any]] = Field(default_factory=list)
    sla_compliant_rate: float = 0.0

    # Rollout
    rollout_schedule: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    compliance_rate: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
