"""PCI Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PCIStage(StrEnum):
    CDE_MAPPING = "cde_mapping"
    REQUIREMENT_CHECK = "requirement_check"
    ASV_SCAN = "asv_scan"
    SAQ_COMPLETION = "saq_completion"
    GENERATE_REPORT = "generate_report"


class Requirement(StrEnum):
    NETWORK_SECURITY = "network_security"
    SECURE_CONFIG = "secure_config"
    PROTECT_DATA = "protect_data"
    VULNERABILITY_MGMT = "vulnerability_mgmt"
    ACCESS_CONTROL = "access_control"
    MONITORING = "monitoring"
    TEST_SECURITY = "test_security"
    POLICY = "policy"


class ScanStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    NOT_APPLICABLE = "not_applicable"


class CDEAsset(BaseModel):
    """Asset within the Cardholder Data Environment."""

    asset_id: str = ""
    hostname: str = ""
    asset_type: str = ""
    stores_pan: bool = False
    stores_cvv: bool = False
    in_scope: bool = True
    network_segment: str = ""
    last_scanned: str = ""


class RequirementCheck(BaseModel):
    """PCI DSS requirement compliance check."""

    check_id: str = ""
    requirement: Requirement = Requirement.NETWORK_SECURITY
    sub_requirement: str = ""
    description: str = ""
    status: ScanStatus = ScanStatus.PENDING
    evidence_refs: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)


class PCIScannerState(BaseModel):
    """Main state for the PCI Scanner agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: PCIStage = PCIStage.CDE_MAPPING

    # Pipeline fields
    cde_assets: list[dict[str, Any]] = Field(default_factory=list)
    requirement_checks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    asv_results: list[dict[str, Any]] = Field(default_factory=list)
    saq_answers: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    assets_scanned: int = 0
    requirements_passed: int = 0
    requirements_failed: int = 0
    compliance_score: float = 0.0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
