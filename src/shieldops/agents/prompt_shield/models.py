"""State models for the Prompt Shield Agent LangGraph workflow."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# 3 StrEnums
# ---------------------------------------------------------------------------


class ShieldStage(StrEnum):
    """Processing stages in the prompt shield pipeline."""

    INGEST = "ingest"
    CLASSIFY = "classify"
    DETECT_INJECTIONS = "detect_injections"
    ANALYZE_JAILBREAKS = "analyze_jailbreaks"
    ENFORCE_POLICIES = "enforce_policies"
    REPORT = "report"
    COMPLETE = "complete"
    FAILED = "failed"


class ThreatType(StrEnum):
    """Categories of prompt-level threats."""

    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    PROMPT_LEAKING = "prompt_leaking"
    DATA_EXFIL = "data_exfil"


class DetectionVerdict(StrEnum):
    """Overall verdict for a scanned prompt."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BLOCKED = "blocked"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class PromptSample(BaseModel):
    """A single prompt submitted for analysis."""

    sample_id: str = ""
    content: str = ""
    source: str = ""
    role: str = "user"
    metadata: dict[str, Any] = Field(default_factory=dict)


class InjectionDetection(BaseModel):
    """Result of injection detection on a prompt sample."""

    sample_id: str = ""
    threat_type: str = ThreatType.DIRECT_INJECTION
    pattern_matched: str = ""
    confidence: float = 0.0
    snippet: str = ""
    verdict: str = DetectionVerdict.CLEAN


class JailbreakAttempt(BaseModel):
    """Result of jailbreak analysis on a prompt sample."""

    sample_id: str = ""
    technique: str = ""
    pattern_matched: str = ""
    confidence: float = 0.0
    snippet: str = ""
    verdict: str = DetectionVerdict.CLEAN


class PolicyEnforcement(BaseModel):
    """Policy enforcement action taken on a prompt."""

    sample_id: str = ""
    action: str = "allow"
    reason: str = ""
    policy_id: str = ""
    original_verdict: str = DetectionVerdict.CLEAN
    enforced_verdict: str = DetectionVerdict.CLEAN


class ReasoningStep(BaseModel):
    """Audit trail entry for the prompt shield workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


# ---------------------------------------------------------------------------
# Agent state
# ---------------------------------------------------------------------------


class PromptShieldState(BaseModel):
    """Full state for a prompt shield workflow run."""

    # Input
    tenant_id: str = ""
    scan_id: str = ""
    prompts: list[PromptSample] = Field(default_factory=list)

    # Classification
    classifications: list[dict[str, Any]] = Field(default_factory=list)

    # Injection detection
    injection_detections: list[InjectionDetection] = Field(default_factory=list)

    # Jailbreak analysis
    jailbreak_attempts: list[JailbreakAttempt] = Field(default_factory=list)

    # Policy enforcement
    enforcement_actions: list[PolicyEnforcement] = Field(default_factory=list)

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Summary metrics
    total_scanned: int = 0
    total_blocked: int = 0
    total_suspicious: int = 0
    total_malicious: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str | None = None
