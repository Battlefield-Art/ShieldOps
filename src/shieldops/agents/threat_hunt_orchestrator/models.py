"""State models for the Threat Hunt Orchestrator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class THOStage(StrEnum):
    """Stages in the threat hunt orchestration lifecycle."""

    GENERATE_HYPOTHESIS = "generate_hypothesis"
    COLLECT_EVIDENCE = "collect_evidence"
    ANALYZE_DATA = "analyze_data"
    VALIDATE_FINDINGS = "validate_findings"
    DOCUMENT_HUNT = "document_hunt"
    REPORT = "report"


class HuntType(StrEnum):
    """Type of threat hunting campaign."""

    HYPOTHESIS_DRIVEN = "hypothesis_driven"
    INTELLIGENCE_DRIVEN = "intelligence_driven"
    SITUATIONAL = "situational"
    AUTOMATED = "automated"


class TacticCategory(StrEnum):
    """MITRE ATT&CK tactic categories for hunt focus."""

    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"


# --- Domain models ---


class HuntHypothesis(BaseModel):
    """A threat hunting hypothesis to investigate."""

    hypothesis_id: str = ""
    statement: str = ""
    hunt_type: HuntType = HuntType.HYPOTHESIS_DRIVEN
    tactic: TacticCategory = TacticCategory.INITIAL_ACCESS
    mitre_techniques: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    priority: str = "medium"


class EvidenceCollection(BaseModel):
    """Evidence collected from queried data sources."""

    source: str = ""
    query: str = ""
    records_found: int = 0
    raw_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    time_range: str = "7d"
    collected_at: datetime | None = None


class DataAnalysis(BaseModel):
    """Analysis result from processing collected evidence."""

    analysis_id: str = ""
    technique: str = ""
    anomalies_detected: int = 0
    patterns: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""


class HuntFinding(BaseModel):
    """A validated finding from the hunt campaign."""

    finding_id: str = ""
    mitre_technique: str = ""
    tactic: TacticCategory = TacticCategory.INITIAL_ACCESS
    severity: str = "low"
    confidence: float = 0.0
    affected_assets: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    description: str = ""
    validated: bool = False


class HuntDocumentation(BaseModel):
    """Documentation artifact for a completed hunt."""

    hunt_id: str = ""
    hypothesis_statement: str = ""
    hunt_type: HuntType = HuntType.HYPOTHESIS_DRIVEN
    findings_count: int = 0
    validated_count: int = 0
    mitre_coverage: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    effectiveness_score: float = 0.0
    duration_ms: int = 0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestrator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ThreatHuntOrchestratorState(BaseModel):
    """Full state for a threat hunt orchestrator run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: THOStage = THOStage.GENERATE_HYPOTHESIS

    # Inputs
    campaign_name: str = ""
    hunt_type: HuntType = HuntType.HYPOTHESIS_DRIVEN
    target_tactics: list[TacticCategory] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    data_sources: list[str] = Field(default_factory=list)

    # Pipeline fields
    hypotheses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    documentation: dict[str, Any] = Field(
        default_factory=dict,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    threat_found: bool = False
    total_findings: int = 0
    validated_findings: int = 0
    effectiveness_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
