"""ISO 27001 Assessor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ISOStage(StrEnum):
    SCOPE_ISMS = "scope_isms"
    ASSESS_CONTROLS = "assess_controls"
    IDENTIFY_GAPS = "identify_gaps"
    RISK_TREATMENT = "risk_treatment"
    SOA = "soa"
    REPORT = "report"


class ControlDomain(StrEnum):
    INFORMATION_SECURITY_POLICIES = "information_security_policies"
    ASSET_MANAGEMENT = "asset_management"
    ACCESS_CONTROL = "access_control"
    CRYPTOGRAPHY = "cryptography"
    PHYSICAL_SECURITY = "physical_security"
    OPERATIONS_SECURITY = "operations_security"


class MaturityLevel(StrEnum):
    INITIAL = "initial"
    MANAGED = "managed"
    DEFINED = "defined"
    QUANTITATIVELY_MANAGED = "quantitatively_managed"
    OPTIMIZING = "optimizing"


class ControlAssessment(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class GapFinding(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class RiskTreatment(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class ISO27001AssessorState(BaseModel):
    request_id: str = ""
    stage: ISOStage = ISOStage.SCOPE_ISMS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
