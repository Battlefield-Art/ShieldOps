"""Browser Isolation Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IsolationStage(StrEnum):
    COLLECT_SESSIONS = "collect_sessions"
    DETECT_BREAKOUTS = "detect_breakouts"
    EVALUATE_POLICIES = "evaluate_policies"
    SANDBOX_CONTENT = "sandbox_content"
    ENFORCE = "enforce"
    REPORT = "report"


class SessionRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class IsolationAction(StrEnum):
    TERMINATE = "terminate"
    BLOCK = "block"
    ISOLATE = "isolate"
    ALLOW = "allow"
    SANDBOX = "sandbox"
    ALERT = "alert"


class BrowserSession(BaseModel):
    """An isolated browser session."""

    session_id: str = ""
    user: str = ""
    url: str = ""
    domain: str = ""
    isolated: bool = True
    risk: SessionRisk = SessionRisk.LOW
    started_at: datetime | None = None
    bytes_transferred: int = 0
    context: dict[str, Any] = Field(default_factory=dict)


class BreakoutAttempt(BaseModel):
    """A detected sandbox breakout attempt."""

    id: str = ""
    session_id: str = ""
    technique: str = ""
    severity: SessionRisk = SessionRisk.HIGH
    blocked: bool = True
    details: str = ""
    detected_at: datetime | None = None


class ContentPolicy(BaseModel):
    """A content isolation policy."""

    id: str = ""
    name: str = ""
    domain_pattern: str = ""
    action: IsolationAction = IsolationAction.ISOLATE
    reason: str = ""
    enabled: bool = True


class BrowserIsolationState(BaseModel):
    """Main state for the Browser Isolation agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: IsolationStage = IsolationStage.COLLECT_SESSIONS

    # Sessions
    sessions: list[dict[str, Any]] = Field(default_factory=list)
    total_sessions: int = 0
    active_isolated: int = 0

    # Breakout detection
    breakout_attempts: list[dict[str, Any]] = Field(default_factory=list)
    breakouts_blocked: int = 0

    # Policies
    policy_violations: list[dict[str, Any]] = Field(default_factory=list)
    policies_enforced: int = 0

    # Sandbox
    sandboxed_content: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    risk_score: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
