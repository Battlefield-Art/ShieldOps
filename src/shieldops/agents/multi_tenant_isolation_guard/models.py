"""State models for the Multi-Tenant Isolation Guard Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ------------------------------------------------


class MTIGStage(StrEnum):
    """Workflow stages for isolation validation."""

    MAP_TENANTS = "map_tenants"
    SCAN_BOUNDARIES = "scan_boundaries"
    DETECT_LEAKAGE = "detect_leakage"
    ASSESS_ISOLATION = "assess_isolation"
    ENFORCE_CONTROLS = "enforce_controls"
    REPORT = "report"


class IsolationType(StrEnum):
    """Type of tenant isolation."""

    NETWORK = "network"
    DATA = "data"
    COMPUTE = "compute"
    STORAGE = "storage"
    APPLICATION = "application"


class LeakageSeverity(StrEnum):
    """Severity of data leakage."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# -- Domain Models -------------------------------------------


class TenantMapping(BaseModel):
    """Mapping of a tenant's resources."""

    tenant_id: str = ""
    resources: list[str] = Field(default_factory=list)
    isolation_type: IsolationType = IsolationType.NETWORK
    namespace: str = ""
    region: str = ""


class BoundaryScan(BaseModel):
    """Result of scanning a tenant boundary."""

    scan_id: str = ""
    tenant_id: str = ""
    boundary_type: IsolationType = IsolationType.NETWORK
    status: str = "intact"
    findings: list[str] = Field(default_factory=list)


class LeakageDetection(BaseModel):
    """Detection of cross-tenant data leakage."""

    detection_id: str = ""
    source_tenant: str = ""
    target_tenant: str = ""
    severity: LeakageSeverity = LeakageSeverity.NONE
    data_type: str = ""
    evidence: str = ""


class IsolationAssessment(BaseModel):
    """Assessment of overall isolation quality."""

    tenant_id: str = ""
    isolation_score: float = 0.0
    gaps: list[str] = Field(default_factory=list)
    compliance_status: str = "compliant"


class ControlEnforcement(BaseModel):
    """Enforcement action for isolation controls."""

    enforcement_id: str = ""
    tenant_id: str = ""
    control_type: str = ""
    action: str = ""
    status: str = "applied"


# -- Reasoning + State ---------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class MultiTenantIsolationGuardState(BaseModel):
    """Full state for the Multi-Tenant Isolation Guard."""

    request_id: str = ""
    tenant_id: str = ""
    stage: MTIGStage = MTIGStage.MAP_TENANTS
    config: dict[str, Any] = Field(default_factory=dict)

    tenant_mappings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    boundary_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    leakage_detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    isolation_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    control_enforcements: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
