"""State models for the Email Authentication Auditor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EmailAuthStage(StrEnum):
    """Stages of the email authentication audit workflow."""

    SCAN_DOMAINS = "scan_domains"
    CHECK_SPF = "check_spf"
    CHECK_DKIM = "check_dkim"
    CHECK_DMARC = "check_dmarc"
    ASSESS_POSTURE = "assess_posture"
    REPORT = "report"


class AuthStatus(StrEnum):
    """Authentication record status."""

    PASS = "pass"
    FAIL = "fail"
    MISSING = "missing"
    PARTIAL = "partial"
    MISCONFIGURED = "misconfigured"
    UNKNOWN = "unknown"


class PolicyMode(StrEnum):
    """DMARC policy modes."""

    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"
    NOT_SET = "not_set"


class DomainRecord(BaseModel):
    """A domain to audit for email authentication."""

    id: str = ""
    domain: str = ""
    mx_records: list[str] = Field(default_factory=list)
    spf_status: AuthStatus = AuthStatus.UNKNOWN
    dkim_status: AuthStatus = AuthStatus.UNKNOWN
    dmarc_status: AuthStatus = AuthStatus.UNKNOWN
    dmarc_policy: PolicyMode = PolicyMode.NOT_SET


class SPFResult(BaseModel):
    """SPF check result for a domain."""

    id: str = ""
    domain: str = ""
    record: str = ""
    status: AuthStatus = AuthStatus.UNKNOWN
    includes_count: int = 0
    lookup_count: int = 0
    issues: list[str] = Field(default_factory=list)


class DKIMResult(BaseModel):
    """DKIM check result for a domain."""

    id: str = ""
    domain: str = ""
    selector: str = ""
    key_size: int = 0
    status: AuthStatus = AuthStatus.UNKNOWN
    issues: list[str] = Field(default_factory=list)


class DMARCResult(BaseModel):
    """DMARC check result for a domain."""

    id: str = ""
    domain: str = ""
    policy: PolicyMode = PolicyMode.NOT_SET
    pct: int = 0
    rua: str = ""
    ruf: str = ""
    status: AuthStatus = AuthStatus.UNKNOWN
    issues: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class EmailAuthenticationAuditorState(BaseModel):
    """Full state of an email authentication audit."""

    # Identity
    request_id: str = ""
    stage: EmailAuthStage = EmailAuthStage.SCAN_DOMAINS
    tenant_id: str = ""

    # Data
    domains: list[dict[str, Any]] = Field(default_factory=list)
    spf_results: list[dict[str, Any]] = Field(default_factory=list)
    dkim_results: list[dict[str, Any]] = Field(default_factory=list)
    dmarc_results: list[dict[str, Any]] = Field(default_factory=list)
    posture_assessment: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    total_domains: int = 0
    domains_compliant: int = 0
    compliance_pct: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
