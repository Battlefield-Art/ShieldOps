"""Zero Day Hunter Agent — Pydantic state and data
models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ZDHStage(StrEnum):
    """Stages in the zero-day hunting lifecycle."""

    MONITOR_FEEDS = "monitor_feeds"
    ANALYZE_EXPLOITS = "analyze_exploits"
    ASSESS_EXPOSURE = "assess_exposure"
    DEVELOP_SIGNATURES = "develop_signatures"
    DEPLOY_MITIGATIONS = "deploy_mitigations"
    REPORT = "report"


class ExploitSeverity(StrEnum):
    """Severity classification for zero-day exploits."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class ExploitType(StrEnum):
    """Types of zero-day exploits being tracked."""

    REMOTE_CODE_EXEC = "remote_code_execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    MEMORY_CORRUPTION = "memory_corruption"
    INJECTION = "injection"
    LOGIC_FLAW = "logic_flaw"


class ThreatFeedItem(BaseModel):
    """An item from a threat intelligence feed."""

    feed_id: str = ""
    source: str = ""
    cve_id: str = ""
    title: str = ""
    description: str = ""
    severity: ExploitSeverity = ExploitSeverity.UNKNOWN
    exploit_type: ExploitType = ExploitType.REMOTE_CODE_EXEC
    affected_products: list[str] = Field(
        default_factory=list,
    )
    published_at: float = 0.0
    exploit_available: bool = False


class ExploitAnalysis(BaseModel):
    """Analysis result for a zero-day exploit."""

    analysis_id: str = ""
    cve_id: str = ""
    exploit_type: ExploitType = ExploitType.REMOTE_CODE_EXEC
    attack_vector: str = ""
    complexity: str = ""
    impact_score: float = 0.0
    exploitability_score: float = 0.0
    mitre_techniques: list[str] = Field(
        default_factory=list,
    )
    analysis_notes: str = ""


class ExposureResult(BaseModel):
    """Exposure assessment for a zero-day."""

    cve_id: str = ""
    exposed_assets: int = 0
    asset_ids: list[str] = Field(default_factory=list)
    exposure_score: float = 0.0
    business_impact: str = ""
    internet_facing: bool = False


class SignatureRule(BaseModel):
    """A detection signature or virtual patch rule."""

    rule_id: str = ""
    cve_id: str = ""
    rule_type: str = ""
    pattern: str = ""
    action: str = ""
    confidence: float = 0.0
    platforms: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """Audit trail entry for the hunting workflow."""

    step_number: int = 0
    action: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_ms: int = 0
    tool_used: str | None = None


class ZeroDayHunterState(BaseModel):
    """Full state for a zero-day hunting run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: ZDHStage = ZDHStage.MONITOR_FEEDS

    # Pipeline fields
    feed_items: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    exploit_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    exposure_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    signatures: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    mitigations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    zero_days_found: int = 0
    critical_exposures: int = 0
    signatures_deployed: int = 0
    mitigations_applied: int = 0

    # Workflow tracking
    session_start: float = 0.0
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
