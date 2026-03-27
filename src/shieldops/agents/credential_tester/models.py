"""State models for the Credential Tester Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CredentialStage(StrEnum):
    """Stages of credential testing."""

    AUDIT_PASSWORD_POLICIES = "audit_password_policies"  # noqa: S105
    check_leaked_credentials = "check_leaked_credentials"
    test_mfa_coverage = "test_mfa_coverage"
    test_credential_rotation = "test_credential_rotation"
    assess_risk = "assess_risk"
    report = "report"


class CredentialRisk(StrEnum):
    """Credential risk classifications."""

    compromised = "compromised"
    weak = "weak"
    stale = "stale"
    shared = "shared"
    no_mfa = "no_mfa"
    compliant = "compliant"


class ValidationMethod(StrEnum):
    """Credential validation methods."""

    haveibeenpwned_hash = "haveibeenpwned_hash"
    policy_check = "policy_check"
    rotation_audit = "rotation_audit"
    mfa_enrollment = "mfa_enrollment"
    complexity_test = "complexity_test"


class PasswordPolicy(BaseModel):
    """Password policy audit result."""

    policy_name: str = ""
    min_length: int = 0
    requires_uppercase: bool = False
    requires_numbers: bool = False
    requires_symbols: bool = False
    max_age_days: int = 0
    history_count: int = 0
    compliant: bool = False
    issues: list[str] = Field(default_factory=list)


class LeakedCredentialCheck(BaseModel):
    """Leaked credential check result.

    NEVER stores actual passwords. Uses k-anonymity
    hash prefix checks only.
    """

    account_id: str = ""
    check_method: str = ValidationMethod.haveibeenpwned_hash
    is_leaked: bool = False
    breach_count: int = 0
    last_breach_date: str = ""


class MFACoverage(BaseModel):
    """MFA enrollment coverage result."""

    account_id: str = ""
    mfa_enabled: bool = False
    mfa_type: str = ""
    last_verified: str = ""
    department: str = ""


class RotationAudit(BaseModel):
    """Credential rotation audit result."""

    account_id: str = ""
    credential_type: str = ""
    last_rotated: str = ""
    age_days: int = 0
    max_age_days: int = 90
    overdue: bool = False


class CredentialRiskScore(BaseModel):
    """Risk score for a credential."""

    account_id: str = ""
    risk_level: str = CredentialRisk.compliant
    risk_score: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class CredentialTesterState(BaseModel):
    """Full state for the credential tester workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CredentialStage = CredentialStage.AUDIT_PASSWORD_POLICIES

    # Input
    account_ids: list[str] = Field(default_factory=list)
    policy_names: list[str] = Field(default_factory=list)

    # Pipeline
    policies_audited: list[dict[str, Any]] = Field(default_factory=list)
    leaked_found: list[dict[str, Any]] = Field(default_factory=list)
    mfa_gaps: list[dict[str, Any]] = Field(default_factory=list)
    rotation_issues: list[dict[str, Any]] = Field(default_factory=list)
    risk_scores: list[dict[str, Any]] = Field(default_factory=list)
    accounts_at_risk: list[dict[str, Any]] = Field(default_factory=list)

    # Output
    report_summary: dict[str, Any] = Field(default_factory=dict)
    overall_risk_score: float = 0.0

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
