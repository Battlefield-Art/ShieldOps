"""Building Management Security Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SecurityStage(StrEnum):
    DISCOVER_SYSTEMS = "discover_systems"
    AUDIT_CONFIGS = "audit_configs"
    CHECK_ACCESS = "check_access"
    DETECT_ANOMALIES = "detect_anomalies"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class BMSSystem(StrEnum):
    HVAC = "hvac"
    LIGHTING = "lighting"
    ELEVATOR = "elevator"
    FIRE_SAFETY = "fire_safety"
    ACCESS_CONTROL = "access_control"
    ENERGY_MANAGEMENT = "energy_management"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ACCEPTABLE = "acceptable"


class SystemAudit(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class SecurityViolation(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class AccessPolicy(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class BuildingManagementSecurityState(BaseModel):
    request_id: str = ""
    stage: SecurityStage = SecurityStage.DISCOVER_SYSTEMS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
