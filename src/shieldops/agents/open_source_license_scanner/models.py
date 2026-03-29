"""Open Source License Scanner Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScanStage(StrEnum):
    DISCOVER_DEPS = "discover_deps"
    IDENTIFY_LICENSES = "identify_licenses"
    CHECK_COMPATIBILITY = "check_compatibility"
    FLAG_VIOLATIONS = "flag_violations"
    RECOMMEND = "recommend"
    REPORT = "report"


class LicenseCategory(StrEnum):
    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    WEAK_COPYLEFT = "weak_copyleft"
    PROPRIETARY = "proprietary"
    PUBLIC_DOMAIN = "public_domain"
    UNKNOWN = "unknown"


class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    VIOLATION = "violation"
    REVIEW_NEEDED = "review_needed"
    EXEMPTED = "exempted"
    PENDING = "pending"


class OpenSourceLicenseScannerState(BaseModel):
    request_id: str = ""
    stage: ScanStage = ScanStage.DISCOVER_DEPS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
