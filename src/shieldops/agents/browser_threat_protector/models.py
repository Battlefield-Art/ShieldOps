"""State models for the Browser Threat Protector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class BTPStage(StrEnum):
    """Workflow stages for browser threat protection."""

    ANALYZE_REQUEST = "analyze_request"
    CHECK_REPUTATION = "check_reputation"
    ISOLATE_SESSION = "isolate_session"
    SCAN_CONTENT = "scan_content"
    ENFORCE_POLICY = "enforce_policy"
    REPORT = "report"


class ThreatCategory(StrEnum):
    """Browser threat categories."""

    MALWARE_DOWNLOAD = "malware_download"
    PHISHING = "phishing"
    DRIVE_BY = "drive_by"
    MALICIOUS_JS = "malicious_js"
    CRYPTOMINER = "cryptominer"
    CREDENTIAL_HARVEST = "credential_harvest"
    CLEAN = "clean"


class ReputationLevel(StrEnum):
    """URL reputation levels."""

    TRUSTED = "trusted"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BLOCKED = "blocked"


# -- Domain Models -----------------------------------------------------


class WebRequest(BaseModel):
    """A web request to be analyzed."""

    request_id: str = ""
    url: str = ""
    domain: str = ""
    method: str = "GET"
    user_agent: str = ""
    source_ip: str = ""
    user_id: str = ""
    timestamp: datetime | None = None
    headers: dict[str, str] = Field(default_factory=dict)


class ReputationResult(BaseModel):
    """URL reputation check result."""

    url: str = ""
    reputation: ReputationLevel = ReputationLevel.UNKNOWN
    category: ThreatCategory = ThreatCategory.CLEAN
    score: float = 0.0
    threat_feeds_matched: int = 0
    first_seen: datetime | None = None
    details: str = ""


class IsolationSession(BaseModel):
    """An isolated browser session."""

    session_id: str = ""
    request_id: str = ""
    url: str = ""
    container_id: str = ""
    started_at: datetime | None = None
    pixel_streamed: bool = False
    file_downloads_blocked: bool = True


class ContentScanResult(BaseModel):
    """Content scan result from isolated session."""

    scan_id: str = ""
    session_id: str = ""
    threats_found: list[str] = Field(default_factory=list)
    malicious_js: bool = False
    drive_by_attempt: bool = False
    credential_form: bool = False
    risk_score: float = 0.0


class PolicyAction(BaseModel):
    """Policy enforcement action."""

    action_id: str = ""
    request_id: str = ""
    action: str = "allow"
    reason: str = ""
    applied_policy: str = ""


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the protector workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class BrowserThreatProtectorState(BaseModel):
    """Full state for the Browser Threat Protector workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: BTPStage = BTPStage.ANALYZE_REQUEST
    protection_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Request analysis
    web_requests: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    request_count: int = 0

    # Reputation
    reputation_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    suspicious_count: int = 0

    # Isolation
    isolation_sessions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    isolated_count: int = 0

    # Content scan
    scan_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    threats_found: int = 0

    # Policy
    policy_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    blocked_count: int = 0

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
