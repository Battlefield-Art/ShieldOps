"""Privacy Consent Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PCMStage(StrEnum):
    DISCOVER_CONSENTS = "discover_consents"
    VALIDATE_RECORDS = "validate_records"
    CHECK_EXPIRY = "check_expiry"
    ENFORCE_PREFERENCES = "enforce_preferences"
    AUDIT_COMPLIANCE = "audit_compliance"
    REPORT = "report"


class ConsentType(StrEnum):
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    FUNCTIONAL = "functional"
    ESSENTIAL = "essential"
    THIRD_PARTY = "third_party"
    RESEARCH = "research"


class ConsentStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"
    PENDING = "pending"
    INVALID = "invalid"


class ConsentRecord(BaseModel):
    """A consent record for a data subject."""

    id: str = ""
    subject_id: str = ""
    consent_type: ConsentType = ConsentType.ESSENTIAL
    status: ConsentStatus = ConsentStatus.PENDING
    granted_at: str = ""
    expires_at: str = ""
    purpose: str = ""
    source: str = ""


class PreferenceEnforcement(BaseModel):
    """Enforcement of a consent preference."""

    consent_id: str = ""
    subject_id: str = ""
    action: str = ""
    enforced: bool = False
    systems_updated: int = 0


class ComplianceAuditEntry(BaseModel):
    """An audit entry for consent compliance."""

    consent_id: str = ""
    compliant: bool = True
    issues: list[str] = Field(default_factory=list)
    audited_at: float = 0.0


class PrivacyConsentManagerState(BaseModel):
    """Main state for the Privacy Consent Manager."""

    request_id: str = ""
    tenant_id: str = ""
    stage: PCMStage = PCMStage.DISCOVER_CONSENTS

    # Pipeline data
    consents: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    enforcements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    audit_entries: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    total_consents: int = 0
    active_consents: int = 0
    expired_consents: int = 0
    withdrawn_consents: int = 0
    compliance_rate: float = 0.0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
