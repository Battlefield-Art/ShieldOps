"""SOX Auditor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SOXStage(StrEnum):
    IDENTIFY_CONTROLS = "identify_controls"
    TEST_CONTROLS = "test_controls"
    EVALUATE_DEFICIENCIES = "evaluate_deficiencies"
    REMEDIATE = "remediate"
    DOCUMENT = "document"
    REPORT = "report"


class ControlCategory(StrEnum):
    ACCESS_CONTROL = "access_control"
    CHANGE_MANAGEMENT = "change_management"
    OPERATIONS = "operations"
    SEGREGATION_OF_DUTIES = "segregation_of_duties"
    MONITORING = "monitoring"
    BACKUP = "backup"


class TestResult(StrEnum):
    EFFECTIVE = "effective"
    DEFICIENT = "deficient"
    MATERIAL_WEAKNESS = "material_weakness"
    SIGNIFICANT_DEFICIENCY = "significant_deficiency"
    NOT_TESTED = "not_tested"


class ITGCControl(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class AuditFinding(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class RemediationItem(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class SOXAuditorState(BaseModel):
    request_id: str = ""
    stage: SOXStage = SOXStage.IDENTIFY_CONTROLS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
