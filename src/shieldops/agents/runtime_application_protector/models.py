"""State models for the Runtime Application Protector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class RAPStage(StrEnum):
    """Stages in the runtime application protection lifecycle."""

    INSTRUMENT_APP = "instrument_app"
    MONITOR_RUNTIME = "monitor_runtime"
    DETECT_ATTACKS = "detect_attacks"
    CLASSIFY_THREAT = "classify_threat"
    PROTECT = "protect"
    REPORT = "report"


class AttackCategory(StrEnum):
    """Category of runtime attack detected."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "deserialization"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"


class ProtectionAction(StrEnum):
    """Action taken to protect the application."""

    BLOCK = "block"
    SANITIZE = "sanitize"
    ALERT = "alert"
    QUARANTINE = "quarantine"
    RATE_LIMIT = "rate_limit"
    LOG_ONLY = "log_only"


# --- Domain models ---


class InstrumentedApp(BaseModel):
    """An application instrumented for runtime protection."""

    app_id: str = ""
    app_name: str = ""
    language: str = ""
    framework: str = ""
    endpoints_count: int = 0
    hooks_installed: int = 0
    instrumented_at: datetime | None = None


class RuntimeEvent(BaseModel):
    """A runtime security event captured by RASP hooks."""

    event_id: str = ""
    app_id: str = ""
    endpoint: str = ""
    attack_category: AttackCategory = AttackCategory.SQL_INJECTION
    payload_snippet: str = ""
    source_ip: str = ""
    risk_score: float = 0.0
    detected_at: datetime | None = None


class ThreatClassification(BaseModel):
    """Classification result for a detected runtime attack."""

    classification_id: str = ""
    event_id: str = ""
    attack_category: AttackCategory = AttackCategory.SQL_INJECTION
    confidence: float = 0.0
    severity: str = "low"
    cwe_ids: list[str] = Field(default_factory=list)
    description: str = ""


class ProtectionRecord(BaseModel):
    """Record of a protection action taken."""

    record_id: str = ""
    event_id: str = ""
    action: ProtectionAction = ProtectionAction.BLOCK
    success: bool = False
    latency_ms: int = 0
    details: str = ""


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the RASP workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class RuntimeApplicationProtectorState(BaseModel):
    """Full state for a runtime application protector run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: RAPStage = RAPStage.INSTRUMENT_APP

    # Inputs
    target_app: str = ""
    language: str = ""
    framework: str = ""
    protection_mode: str = "enforce"
    endpoints: list[str] = Field(default_factory=list)

    # Pipeline fields
    instrumentation: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    runtime_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    detected_attacks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    protections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_events: int = 0
    attacks_blocked: int = 0
    attacks_detected: int = 0
    false_positive_rate: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
