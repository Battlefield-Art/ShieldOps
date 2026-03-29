"""MFA Compliance Checker Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CheckStage(StrEnum):
    DISCOVER_ACCOUNTS = "discover_accounts"
    CHECK_MFA_STATUS = "check_mfa_status"
    CLASSIFY_RISK = "classify_risk"
    ENFORCE_POLICY = "enforce_policy"
    REPORT_GAPS = "report_gaps"
    REPORT = "report"


class MFAMethod(StrEnum):
    TOTP = "totp"
    WEBAUTHN = "webauthn"
    SMS = "sms"
    EMAIL = "email"
    PUSH = "push"
    HARDWARE_KEY = "hardware_key"


class ComplianceLevel(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    EXEMPT = "exempt"
    PENDING = "pending"


class MfaComplianceCheckerState(BaseModel):
    request_id: str = ""
    stage: CheckStage = CheckStage.DISCOVER_ACCOUNTS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
